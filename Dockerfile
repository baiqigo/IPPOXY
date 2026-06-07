FROM python:3.13-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    OUTLOOK_BROWSER_PATH=/usr/bin/chromium

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    chromium \
    fonts-liberation \
    fonts-noto-cjk \
    xauth \
    xvfb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p Results captures .profiles

ENTRYPOINT ["xvfb-run", "-a", "--server-args=-screen 0 1365x768x24"]
CMD ["python", "main.py"]
