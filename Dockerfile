FROM python:3.12-slim

# Встановлюємо системні пакети
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        git \
        build-essential \
        python3-dev \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Встановлюємо Python-пакети
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        requests \
        colorama \
        Pillow \
        pycryptodome \
        pysolarmanv5 \
        python-miio

# Встановлюємо робочу директорію
WORKDIR /workspace

# Встановлюємо bash як вхідну точку для інтерактивної роботи
ENTRYPOINT ["bash"]

