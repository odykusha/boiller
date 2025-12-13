import warnings
warnings.filterwarnings('ignore', category=FutureWarning)

import json
import logging
import time
from pysolarmanv5 import PySolarmanV5
from miio import ChuangmiPlug


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(handler)
logger.propagate = False

SOC_LEVEL = 95
HOME_LOAD = 2000
MAX_HOME_LOAD = 4000

with open('config.json', 'r') as f:
    config = json.load(f)
    c_deye = config['deye']
    c_mijia = config['mijia']


class Deye:
    def __init__(self):
        self.inverter = PySolarmanV5(
            address=c_deye['ip'],
            serial=c_deye['serial'],
            port=8899,
            mb_slave_id=1,
            verbose=False,
        )
        def get_register(register_soc):
            result = self.inverter.read_holding_registers(
                register_addr=register_soc,
                quantity=1,
            )
            return result[0]

        self.battery_soc = get_register(184)
        self.grid_load = get_register(167)
        self.home_load = get_register(176)
    
    def is_grid_on(self):
        light = self.grid_load > 0
        return light
    
    def is_grid_off(self):
        return not self.is_grid_on()


class Mijia:
    def __init__(self):
        self.plug = ChuangmiPlug(
            ip=c_mijia['ip'],
            token=c_mijia['token'],
        )
    
    def on(self):
        self.plug.on()
    
    def off(self):
        self.plug.off()

    # def is_on(self):
    #     status = self.plug.status().is_on
    #     return status


def change_boiller():
    deye = Deye()
    mijia = Mijia()
    info = f"батарея: {deye.battery_soc}%, мережа: {deye.grid_load} Вт, дім: {deye.home_load} Вт"
    
    if deye.is_grid_off():
        logger.info(f"🕯️ Мережі немає, Бойлер ВИМКНЕНО 🪫. {info}")
        mijia.off()
    elif deye.is_grid_on() and deye.battery_soc >= SOC_LEVEL and deye.home_load <= HOME_LOAD:
        logger.info(f"💡 Мережа є, Батареї {SOC_LEVEL}%, Бойлер УВІМКНЕНО 🔋. {info}")
        mijia.on()
    elif deye.is_grid_on() and deye.home_load >= MAX_HOME_LOAD:
        logger.info(f"💡 Мережа є, Дім занадто великий - {deye.home_load} Вт, Бойлер ВИМКНЕНО 🔋. {info}")
        mijia.off()
    else:
        logger.info(f"⏳ Мережа є, Чекаємо зарядження батареї. {info}")


if __name__ == "__main__":
    logger.info("🚀 Бойлер-контролер запущено. Перевірка кожні 60 секунд...")
    
    while True:
        try:
            change_boiller()
        except Exception as e:
            logger.error(f"❌ Помилка: {e}")
        
        time.sleep(60)
