FROM python:3.12-slim

# Встановлюємо системні пакети
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

# Базові пакети
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

# PyTorch CPU (окремий шар для кешування)
RUN pip install --no-cache-dir \
        torch torchvision \
        --index-url https://download.pytorch.org/whl/cpu

# AI моделі
RUN pip install --no-cache-dir \
        basicsr \
        facexlib \
        realesrgan \
        gfpgan \
        deoldify

# CodeFormer (немає офіційного pip-пакету)
RUN pip install --no-cache-dir git+https://github.com/sczhou/CodeFormer.git

# Встановлюємо робочу директорію
WORKDIR /workspace
