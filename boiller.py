import warnings
warnings.filterwarnings('ignore', category=FutureWarning)

from pysolarmanv5 import PySolarmanV5
from miio import ChuangmiPlug, DeviceException



def get_deye_battery_soc():
    logger_ip = "192.168.50.160"
    logger_port = 8899
    logger_serial = 2992401876
    # Регістр для Battery SOC (State of Charge).
    register_soc = 184

    inverter = PySolarmanV5(
        logger_ip,
        logger_serial,
        port=logger_port,
        mb_slave_id=1,
        verbose=False,
    )
    result = inverter.read_holding_registers(
        register_addr=register_soc,
        quantity=1,
    )
    soc_value = result[0]
    print(f"[Deye] 🔋 Рівень заряду батареї: {soc_value}%")


def mijia(action):
    # NAME:     ялинка
    # ID:       120047690
    # MAC:      40:31:3C:D9:3D:C9
    # IP:       192.168.50.176
    # TOKEN:    688abef67428fdcc540797d198a6740d

    PLUG_IP = "192.168.50.176"  # IP розетки з Token Extractor
    PLUG_TOKEN = "688abef67428fdcc540797d198a6740d"  # 32-символьний токен
    try:
        # Ініціалізація розетки
        plug = ChuangmiPlug(ip=PLUG_IP, token=PLUG_TOKEN)

        if action == "on":
            plug.on()
            print("[Mijia] ✅ Розетка УВІМКНЕНА")

        elif action == "off":
            plug.off()
            print("[Mijia] ❌ Розетка ВИМКНЕНА")

        elif action == "status":
            info = plug.status()
            print(f"[Mijia] ℹ️ Статус: {'Увімкнено' if info.is_on else 'Вимкнено'}")
            return info.is_on

    except DeviceException as e:
        print(f"[Mijia] ⚠️ Помилка з'єднання з розеткою: {e}")


if __name__ == "__main__":
    get_deye_battery_soc()
    # mijia('off')


