from PIL import Image, ImageEnhance
import cv2
import numpy as np
import io
import base64
import os
import urllib.request

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')


def _decode(data_url: str) -> Image.Image:
    data = data_url.split(',', 1)[1] if ',' in data_url else data_url
    return Image.open(io.BytesIO(base64.b64decode(data))).convert('RGB')


def _encode(img: Image.Image, quality: int = 95) -> str:
    buf = io.BytesIO()
    img.save(buf, format='JPEG', quality=quality)
    return 'data:image/jpeg;base64,' + base64.b64encode(buf.getvalue()).decode()


def _encode_png(img: Image.Image) -> str:
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode()


def _get_model(filename: str, url: str) -> str:
    os.makedirs(MODELS_DIR, exist_ok=True)
    path = os.path.join(MODELS_DIR, filename)
    if not os.path.exists(path):
        urllib.request.urlretrieve(url, path)
    return path


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
    """FSRCNN super-resolution via OpenCV DNN (~30 KB model)."""
    if not hasattr(cv2, 'dnn_superres'):
        raise ImportError('pip install opencv-contrib-python-headless')
    model_path = _get_model(
        f'FSRCNN_x{scale}.pb',
        f'https://raw.githubusercontent.com/Saafke/FSRCNN_Tensorflow/master/models/FSRCNN_x{scale}.pb',
    )
    img = _decode(data_url)
    arr = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
    sr = cv2.dnn_superres.DnnSuperResImpl_create()
    sr.readModel(model_path)
    sr.setModel('fsrcnn', scale)
    return _encode(Image.fromarray(cv2.cvtColor(sr.upsample(arr), cv2.COLOR_BGR2RGB)))


def realesrgan_upscale(data_url: str, scale: int = 4) -> str:
    """Real-ESRGAN super-resolution — best quality upscaling."""
    try:
        from realesrgan import RealESRGANer
        from basicsr.archs.rrdbnet_arch import RRDBNet
    except ImportError:
        raise ImportError('pip install realesrgan basicsr torch torchvision')
    model_path = _get_model(
        f'RealESRGAN_x{scale}plus.pth',
        f'https://github.com/xinntao/Real-ESRGAN/releases/download/v0.1.0/RealESRGAN_x{scale}plus.pth',
    )
    model = RRDBNet(num_in_ch=3, num_out_ch=3, num_feat=64, num_block=23, num_grow_ch=32, scale=scale)
    upsampler = RealESRGANer(
        scale=scale, model_path=model_path, model=model,
        tile=512, tile_pad=10, pre_pad=0, half=False,
    )
    img = _decode(data_url)
    arr = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
    output, _ = upsampler.enhance(arr, outscale=scale)
    return _encode(Image.fromarray(cv2.cvtColor(output, cv2.COLOR_BGR2RGB)))


def gfpgan_restore(data_url: str) -> str:
    """GFPGAN — face restoration and enhancement."""
    try:
        from gfpgan import GFPGANer
    except ImportError:
        raise ImportError('pip install gfpgan basicsr torch torchvision')
    model_path = _get_model(
        'GFPGANv1.4.pth',
        'https://github.com/TencentARC/GFPGAN/releases/download/v1.3.4/GFPGANv1.4.pth',
    )
    restorer = GFPGANer(
        model_path=model_path, upscale=1,
        arch='clean', channel_multiplier=2, bg_upsampler=None,
    )
    img = _decode(data_url)
    arr = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
    _, _, restored = restorer.enhance(arr, has_aligned=False, only_center_face=False, paste_back=True)
    if restored is None:
        raise ValueError('Обличчя не знайдено на фото')
    return _encode(Image.fromarray(cv2.cvtColor(restored, cv2.COLOR_BGR2RGB)))


def codeformer_restore(data_url: str, fidelity: float = 0.7) -> str:
    """CodeFormer — face restoration with controllable fidelity."""
    try:
        import torch
        from basicsr.utils import img2tensor, tensor2img
        from facexlib.utils.face_restoration_helper import FaceRestoreHelper
    except ImportError:
        raise ImportError('pip install basicsr facexlib torch torchvision')
    try:
        from basicsr.archs.codeformer_arch import CodeFormer as CodeFormerNet
    except ImportError:
        raise ImportError('pip install git+https://github.com/sczhou/CodeFormer.git')

    model_path = _get_model(
        'codeformer.pth',
        'https://github.com/sczhou/CodeFormer/releases/download/v0.1.0/codeformer.pth',
    )
    device = torch.device('cpu')
    net = CodeFormerNet(
        dim_embd=512, codebook_size=1024, n_head=8, n_layers=9,
        connect_list=['32', '64', '128', '256'],
    ).to(device)
    checkpoint = torch.load(model_path, map_location=device)
    net.load_state_dict(checkpoint['params_ema'])
    net.eval()

    img = _decode(data_url)
    arr = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
    face_helper = FaceRestoreHelper(
        1, face_size=512, crop_ratio=(1, 1),
        det_model='retinaface_resnet50', save_ext='png',
        use_parse=True, device=device,
    )
    face_helper.read_image(arr)
    face_helper.get_face_landmarks_5(only_center_face=False, resize=640, eye_dist_threshold=5)
    face_helper.align_warp_face()

    for cropped_face in face_helper.cropped_faces:
        face_t = img2tensor(cropped_face / 255., bgr2rgb=True, float32=True).unsqueeze(0).to(device)
        with torch.no_grad():
            output = net(face_t, w=fidelity, adain=True)[0]
        face_helper.add_restored_face(tensor2img(output, rgb2bgr=True, min_max=(-1, 1)))

    face_helper.get_inverse_affine(None)
    restored = face_helper.paste_faces_to_input_image()
    return _encode(Image.fromarray(cv2.cvtColor(restored, cv2.COLOR_BGR2RGB)))


def deoldify_colorize(data_url: str, render_factor: int = 35) -> str:
    """DeOldify — colorize black & white photos."""
    try:
        import torch
        from deoldify.visualize import get_image_colorizer
    except ImportError:
        raise ImportError('pip install deoldify torch torchvision')

    import tempfile, pathlib
    img = _decode(data_url)

    with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as f:
        tmp_in = f.name
    img.save(tmp_in, 'JPEG', quality=95)

    try:
        colorizer = get_image_colorizer(artistic=False)
        result_path = colorizer.get_transformed_image_path(
            path=pathlib.Path(tmp_in),
            render_factor=render_factor,
            watermarked=False,
        )
        result = Image.open(str(result_path))
        encoded = _encode(result)
    finally:
        os.unlink(tmp_in)

    return encoded


def remove_bg(data_url: str) -> str:
    """Remove background using rembg (ONNX-based, no PyTorch needed)."""
    try:
        from rembg import remove as rembg_remove
    except ImportError:
        raise ImportError('pip install rembg onnxruntime')
    img = _decode(data_url)
    result = rembg_remove(img)
    return _encode_png(result)
