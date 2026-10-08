import warnings
warnings.filterwarnings('ignore', category=FutureWarning)

import json
import logging
import time
from pysolarmanv5 import PySolarmanV5
from miio import ChuangmiPlug, DeviceException
from data_storage import storage


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(handler)
logger.propagate = False

SOC_LEVEL = 80
HOME_LOAD = 5000
MAX_HOME_LOAD = 6000

with open('config.json', 'r') as f:
    config = json.load(f)
    c_deye = config['deye']
    c_mijia = config['mijia']


class Deye:
    def __init__(self):
        try:
            self.inverter = PySolarmanV5(
                address=c_deye['ip'],
                serial=c_deye['serial'],
                port=8899,
                mb_slave_id=1,
                verbose=False,
            )
        except Exception as e:
            logger.error(f'[❌Deye]: {e}')

    def get_register(self, register_soc):
        try:
            result = self.inverter.read_holding_registers(
                register_addr=register_soc,
                quantity=1,
            )
        except Exception as e:
            logger.error(f'[❌Deye] не вдалось прочитати регістр {register_soc}: {e}')
            return None
        return result[0]
    
    @property
    def battery_soc(self):
        return self.get_register(184)
    
    @property
    def grid_load(self):
        return self.get_register(167)
    
    @property
    def home_load(self):
        return self.get_register(176)
    


class Mijia:
    def __init__(self):
        # Конструктор ні до чого не підключається, handshake з розеткою
        # відбувається при першій команді on()/off()
        self.plug = ChuangmiPlug(
            ip=c_mijia['ip'],
            token=c_mijia['token'],
        )

    def on(self):
        try:
            self.plug.on()
        except (DeviceException, OSError) as e:
            logger.error(f'[❌Mijia] не вдалось увімкнути: {e}')

    def off(self):
        try:
            self.plug.off()
        except (DeviceException, OSError) as e:
            logger.error(f'[❌Mijia] не вдалось вимкнути: {e}')

    # def is_on(self):
    #     status = self.plug.status().is_on
    #     return status


def change_boiller(deye, mijia):
    if not hasattr(deye, 'inverter'):
        logger.error('[Deye не робить]. Нічого не міняю')
        return

    # Читаємо кожен регістр один раз, щоб не ходити до інвертора повторно
    battery_soc = deye.battery_soc
    grid_load = deye.grid_load
    home_load = deye.home_load
    if None in (battery_soc, grid_load, home_load):
        logger.error('[Deye не відповідає]. Нічого не міняю')
        return

    # Зберігаємо дані для графіків
    storage.add_record(battery_soc, grid_load, home_load)
    info = f"батарея: {battery_soc}%, мережа: {grid_load} Вт, дім: {home_load} Вт"
    grid_on = grid_load > 0

    if not grid_on:
        logger.info(f"🕯️ Мережі немає, Бойлер ВИМКНЕНО 🪫. {info}")
        mijia.off()
    elif battery_soc >= SOC_LEVEL and home_load <= HOME_LOAD:
        logger.info(f"💡 Мережа є, Батареї {SOC_LEVEL}%, Бойлер УВІМКНЕНО 🔋. {info}")
        mijia.on()
    elif home_load >= MAX_HOME_LOAD:
        logger.info(f"💡 Мережа є, Дім занадто великий - {home_load} Вт, Бойлер ВИМКНЕНО 🪫. {info}")
        mijia.off()
    else:
        logger.info(f"⏳ Мережа є, Чекаємо зарядження батареї. {info}")


if __name__ == "__main__":
    logger.info("🚀 Бойлер-контролер запущено. Перевірка кожні 60 секунд...")

    deye = Deye()
    mijia = Mijia()

    while True:
        # reload
        if not hasattr(deye, 'inverter'):
            deye = Deye()

        try:
            change_boiller(deye, mijia)
        except Exception:
            # Несподівана помилка: стек у той самий формат логів
            logger.exception("❌ Помилка")
        finally:
            # Зберігаємо історію на диск перед сном
            storage.save_history()
        
        time.sleep(60)
