from PIL import Image, ImageEnhance
import cv2
import numpy as np
import io
import base64


def _decode(data_url: str) -> Image.Image:
    data = data_url.split(',', 1)[1] if ',' in data_url else data_url
    return Image.open(io.BytesIO(base64.b64decode(data))).convert('RGB')


def _encode(img: Image.Image, quality: int = 95) -> str:
    buf = io.BytesIO()
    img.save(buf, format='JPEG', quality=quality)
    return 'data:image/jpeg;base64,' + base64.b64encode(buf.getvalue()).decode()


def enhance(data_url: str, *, contrast=1.0, brightness=1.0,
            saturation=1.0, sharpness=1.0, denoise=0) -> str:
    img = _decode(data_url)

    if brightness != 1.0:
        img = ImageEnhance.Brightness(img).enhance(brightness)
    if contrast != 1.0:
        img = ImageEnhance.Contrast(img).enhance(contrast)
    if saturation != 1.0:
        img = ImageEnhance.Color(img).enhance(saturation)
    if denoise > 0:
        arr = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
        h = max(1, int(denoise))
        arr = cv2.fastNlMeansDenoisingColored(arr, None, h, h, 7, 21)
        img = Image.fromarray(cv2.cvtColor(arr, cv2.COLOR_BGR2RGB))
    if sharpness != 1.0:
        img = ImageEnhance.Sharpness(img).enhance(sharpness)

    return _encode(img)


def ai_enhance(data_url: str, scale: int = 2) -> str:
    """AI super-resolution via OpenCV DNN (FSRCNN). Requires opencv-contrib-python-headless."""
    if not hasattr(cv2, 'dnn_superres'):
        raise ImportError('pip install opencv-contrib-python-headless')

    import os
    import urllib.request

    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    os.makedirs(models_dir, exist_ok=True)
    model_path = os.path.join(models_dir, f'FSRCNN_x{scale}.pb')

    if not os.path.exists(model_path):
        url = (f'https://raw.githubusercontent.com/Saafke/FSRCNN_Tensorflow/'
               f'master/models/FSRCNN_x{scale}.pb')
        urllib.request.urlretrieve(url, model_path)

    img = _decode(data_url)
    arr = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)

    sr = cv2.dnn_superres.DnnSuperResImpl_create()
    sr.readModel(model_path)
    sr.setModel('fsrcnn', scale)
    output = sr.upsample(arr)

    return _encode(Image.fromarray(cv2.cvtColor(output, cv2.COLOR_BGR2RGB)))
