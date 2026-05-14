FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        git \
        build-essential \
        python3-dev \
        libc6-dev \
        libglib2.0-0 \
        libgl1 \
    && rm -rf /var/lib/apt/lists/*

# Базові пакети (без PyTorch)
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        requests \
        colorama \
        Pillow \
        pycryptodome \
        pysolarmanv5 \
        python-miio \
        flask \
        flask-cors \
        numpy \
        opencv-contrib-python-headless \
        onnxruntime \
        rembg

# PyTorch CPU — окремий шар для кешування
RUN pip install --no-cache-dir \
    torch torchvision \
    --index-url https://download.pytorch.org/whl/cpu

# AI пакети — --no-build-isolation щоб не перезавантажувати torch як build-dep
RUN pip install --no-cache-dir --no-build-isolation \
    basicsr \
    facexlib \
    gfpgan && \
    find /usr/local/lib -path "*/basicsr/*" -name "*.py" -exec \
        sed -i 's/from torchvision\.transforms\.functional_tensor import/from torchvision.transforms.functional import/g' {} \;

# basicsr замінює opencv-contrib на opencv-python — відновлюємо contrib
RUN pip install --no-cache-dir --force-reinstall opencv-contrib-python-headless




WORKDIR /workspace
