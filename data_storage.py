"""
Модуль для зберігання історії даних інвертера
"""
import json
import threading
from datetime import datetime
from collections import deque
from pathlib import Path

# Максимальна кількість записів для зберігання (останні 24 години при перевірці кожні 60 сек = 1440 записів)
MAX_RECORDS = 1440

class DataStorage:
    def __init__(self, data_file='data_history.json'):
        self.data_file = Path(data_file)
        self.lock = threading.Lock()
        # Використовуємо deque для ефективного зберігання останніх записів
        self.history = deque(maxlen=MAX_RECORDS)
        self.load_history()
    
    def add_record(self, battery_soc, grid_load, home_load):
        """Додає новий запис до історії"""
        record = {
            'timestamp': datetime.now().isoformat(),
            'battery_soc': battery_soc,
            'grid_load': grid_load,
            'home_load': home_load,
            'grid_status': grid_load > 0,  # True якщо є світло, False якщо немає
        }
        
        with self.lock:
            self.history.append(record)
        self.save_history()
    
    def get_history(self, limit=None):
        """Перезавантажує історію з диску (корисно коли файл оновлюється іншим процесом)"""
        self.load_history()

        """Отримує історію даних"""
        with self.lock:
            history_list = list(self.history)
            if limit:
                return history_list[-limit:]
            return history_list
    
    def get_latest(self):
        """Перезавантажує історію з диску (корисно коли файл оновлюється іншим процесом)"""
        self.load_history()

        """Отримує останній запис"""
        with self.lock:
            if self.history:
                return self.history[-1]
            return None
    
    def save_history(self):
        """Зберігає історію на диск"""
        try:
            with self.lock:
                history_list = list(self.history)
            with open(self.data_file, 'w') as f:
                json.dump(history_list, f, indent=2)
        except Exception as e:
            print(f"Помилка збереження історії: {e}")
    
    def load_history(self):
        """Завантажує історію з диску"""
        try:
            if self.data_file.exists():
                with open(self.data_file, 'r') as f:
                    history_list = json.load(f)
                with self.lock:
                    self.history = deque(history_list[-MAX_RECORDS:], maxlen=MAX_RECORDS)
                    print(f"Завантажено {len(self.history)} записів з {self.data_file}")
        except Exception as e:
            print(f"Помилка завантаження історії: {e}")
    
# Глобальний екземпляр для використання в інших модулях
storage = DataStorage()
