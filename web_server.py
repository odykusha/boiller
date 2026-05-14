"""
Веб-сервер для відображення графіків даних інвертера
"""
from flask import Flask, render_template, jsonify, send_from_directory, request
from flask_cors import CORS
from data_storage import storage
import os
from photo_enhancer import enhance, ai_enhance, edsr_enhance, remove_bg

app = Flask(__name__)
CORS(app)  # Дозволяємо CORS для API

# Шлях до APK файлу
APK_FOLDER = os.path.join(os.path.dirname(__file__), 'app')

@app.route('/')
def index():
    """Головна сторінка з графіками"""
    return render_template('index.html')

@app.route('/<path:page>')
def serve_page(page):
    """Відображення будь-якого HTML файлу з директорії templates"""
    if not page.endswith('.html'):
        page = page + '.html'
    return render_template(page)

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

@app.route('/api/enhance', methods=['POST'])
def api_enhance():
    data = request.get_json()
    try:
        result = enhance(
            data['image'],
            contrast=float(data.get('contrast', 1.0)),
            brightness=float(data.get('brightness', 1.0)),
            saturation=float(data.get('saturation', 1.0)),
            sharpness=float(data.get('sharpness', 1.0)),
            denoise=float(data.get('denoise', 0)),
        )
        return jsonify({'enhanced': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai-enhance', methods=['POST'])
def api_ai_enhance():
    data = request.get_json()
    try:
        result = ai_enhance(data['image'], scale=int(data.get('scale', 2)))
        return jsonify({'enhanced': result})
    except ImportError as e:
        return jsonify({'error': 'not_installed', 'message': str(e)}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/edsr-enhance', methods=['POST'])
def api_edsr_enhance():
    data = request.get_json()
    try:
        result = edsr_enhance(data['image'], scale=int(data.get('scale', 4)))
        return jsonify({'enhanced': result})
    except ImportError as e:
        return jsonify({'error': 'not_installed', 'message': str(e)}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/remove-bg', methods=['POST'])
def api_remove_bg():
    data = request.get_json()
    try:
        result = remove_bg(data['image'])
        return jsonify({'enhanced': result})
    except ImportError as e:
        return jsonify({'error': 'not_installed', 'message': str(e)}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/download/<path:filename>')
def download_app(filename):
    """Скачування APK файлу"""
    return send_from_directory(APK_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    port = int(os.environ.get('WEB_PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

