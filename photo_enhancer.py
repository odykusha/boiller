from PIL import Image, ImageEnhance
import cv2
import numpy as np
import io
import base64
import os
import urllib.request

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
Image.MAX_IMAGE_PIXELS = None


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
    # FSRCNN overflows on large inputs — cap at 1024px longest side
    max_side = 1024
    w, h = img.size
    if max(w, h) > max_side:
        ratio = max_side / max(w, h)
        img = img.resize((int(w * ratio), int(h * ratio)), Image.LANCZOS)
    arr = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
    sr = cv2.dnn_superres.DnnSuperResImpl_create() if hasattr(cv2.dnn_superres, 'DnnSuperResImpl_create') else cv2.dnn_superres.DnnSuperResImpl()
    sr.readModel(model_path)
    sr.setModel('fsrcnn', scale)
    return _encode(Image.fromarray(cv2.cvtColor(sr.upsample(arr), cv2.COLOR_BGR2RGB)))



def gfpgan_restore(data_url: str) -> str:
    """GFPGAN — face restoration and enhancement."""
    try:
        from gfpgan import GFPGANer
    except ModuleNotFoundError as e:
        raise ImportError(f'pip install gfpgan basicsr torch torchvision (missing: {e})')
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



def colorize_bw(data_url: str) -> str:
    """Colorize B&W photos using ECCV16 model (Zhang et al., no extra packages)."""
    import torch
    import torch.nn as nn
    from skimage import color as skcolor

    model_path = _get_model(
        'eccv16_colorizer.pth',
        'https://colorizers.s3.us-east-2.amazonaws.com/eccv16-opt.pth',
    )

    class _ECCV16(nn.Module):
        def __init__(self):
            super().__init__()
            self.model1 = nn.Sequential(
                nn.Conv2d(1,64,3,1,1), nn.ReLU(True), nn.Conv2d(64,64,3,2,1), nn.ReLU(True), nn.BatchNorm2d(64))
            self.model2 = nn.Sequential(
                nn.Conv2d(64,128,3,1,1), nn.ReLU(True), nn.Conv2d(128,128,3,2,1), nn.ReLU(True), nn.BatchNorm2d(128))
            self.model3 = nn.Sequential(
                nn.Conv2d(128,256,3,1,1), nn.ReLU(True), nn.Conv2d(256,256,3,1,1), nn.ReLU(True),
                nn.Conv2d(256,256,3,2,1), nn.ReLU(True), nn.BatchNorm2d(256))
            self.model4 = nn.Sequential(
                nn.Conv2d(256,512,3,1,1), nn.ReLU(True), nn.Conv2d(512,512,3,1,1), nn.ReLU(True),
                nn.Conv2d(512,512,3,1,1), nn.ReLU(True), nn.BatchNorm2d(512))
            self.model5 = nn.Sequential(
                nn.Conv2d(512,512,3,dilation=2,stride=1,padding=2), nn.ReLU(True),
                nn.Conv2d(512,512,3,dilation=2,stride=1,padding=2), nn.ReLU(True),
                nn.Conv2d(512,512,3,dilation=2,stride=1,padding=2), nn.ReLU(True), nn.BatchNorm2d(512))
            self.model6 = nn.Sequential(
                nn.Conv2d(512,512,3,dilation=2,stride=1,padding=2), nn.ReLU(True),
                nn.Conv2d(512,512,3,dilation=2,stride=1,padding=2), nn.ReLU(True),
                nn.Conv2d(512,512,3,dilation=2,stride=1,padding=2), nn.ReLU(True), nn.BatchNorm2d(512))
            self.model7 = nn.Sequential(
                nn.Conv2d(512,512,3,1,1), nn.ReLU(True), nn.Conv2d(512,512,3,1,1), nn.ReLU(True),
                nn.Conv2d(512,512,3,1,1), nn.ReLU(True), nn.BatchNorm2d(512))
            self.model8 = nn.Sequential(
                nn.ConvTranspose2d(512,256,4,2,1), nn.ReLU(True),
                nn.Conv2d(256,256,3,1,1), nn.ReLU(True), nn.Conv2d(256,256,3,1,1), nn.ReLU(True),
                nn.Conv2d(256,313,1))
            self.softmax = nn.Softmax(dim=1)
            self.model_out = nn.Conv2d(313,2,1,bias=False)
            self.upsample4 = nn.Upsample(scale_factor=4, mode='bilinear', align_corners=False)

        def forward(self, x):
            x = (x - 50.) / 100.
            x = self.model8(self.model7(self.model6(self.model5(
                self.model4(self.model3(self.model2(self.model1(x))))))))
            return self.upsample4(self.model_out(self.softmax(x))) * 110.

    net = _ECCV16()
    net.load_state_dict(torch.load(model_path, map_location='cpu', weights_only=True))
    net.eval()

    img = _decode(data_url)
    img_np = np.array(img).astype(np.float32) / 255.
    img_lab = skcolor.rgb2lab(img_np)
    H, W = img_lab.shape[:2]

    img_l_rs = cv2.resize(img_lab[:, :, 0], (256, 256), interpolation=cv2.INTER_LINEAR)
    tens = torch.from_numpy(img_l_rs[None, None]).float()
    with torch.no_grad():
        ab_rs = net(tens)[0].numpy().transpose(1, 2, 0)

    ab_orig = cv2.resize(ab_rs, (W, H), interpolation=cv2.INTER_LINEAR)
    out_lab = np.concatenate([img_lab[:, :, 0:1], ab_orig], axis=2)
    out_rgb = np.clip(skcolor.lab2rgb(out_lab), 0, 1)
    return _encode(Image.fromarray((out_rgb * 255).astype(np.uint8)))


def remove_bg(data_url: str) -> str:
    """Remove background using rembg (ONNX-based, no PyTorch needed)."""
    try:
        from rembg import remove as rembg_remove
    except ImportError:
        raise ImportError('pip install rembg onnxruntime')
    img = _decode(data_url)
    result = rembg_remove(img)
    return _encode_png(result)
