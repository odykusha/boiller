"""
Веб-сервер для відображення графіків даних інвертера
"""
from flask import Flask, render_template, jsonify, send_from_directory
from flask_cors import CORS
from data_storage import storage
import os

app = Flask(__name__)
CORS(app)  # Дозволяємо CORS для API

# Шлях до APK файлу
APK_FOLDER = os.path.join(os.path.dirname(__file__), 'app')

@app.route('/')
def index():
    """Головна сторінка з графіками"""
    return render_template('index.html')

@app.route('/api/data')
def get_data():
    """API endpoint для отримання даних"""
    # Перезавантажуємо дані з файлу перед відправкою
    history = storage.get_history(limit=1440)
    print(f"API /api/data: повертаємо {len(history)} записів")
    return jsonify({
        'data': history,
        'count': len(history)
    })

@app.route('/api/latest')
def get_latest():
    """API endpoint для отримання останніх даних"""
    latest = storage.get_latest()
    if latest:
        return jsonify(latest)
    return jsonify({'error': 'No data available'}), 404

@app.route('/download/<path:filename>')
def download_app(filename):
    """Скачування APK файлу"""
    return send_from_directory(APK_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    port = int(os.environ.get('WEB_PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

