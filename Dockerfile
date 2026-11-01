# Dockerfile - 20점 Basic Reflected XSS 문제 서버
# 격리된 CTF 실습 환경에서만 사용하세요.
#
# FLAG 는 이미지에 넣지 않습니다. 실행할 때 환경변수 CTF_FLAG 로 주입합니다.
#   docker run -p 8080:8080 --shm-size=256m -e CTF_FLAG='<플래그 값>' <image>

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app

# root 단계: Flask, gunicorn, Playwright + Chromium(시스템 의존성 포함) 설치
RUN pip install --no-cache-dir Flask==3.1.3 gunicorn==23.0.0 playwright==1.63.0 \
    && playwright install --with-deps chromium \
    && chmod -R a+rX /ms-playwright \
    && rm -rf /var/lib/apt/lists/* \
    && adduser --disabled-password --gecos "" appuser

COPY --chown=appuser:appuser app.py /app/app.py

# Chromium 샌드박스는 root 로 실행되지 않으므로 일반 사용자로 실행한다.
USER appuser

EXPOSE 8080

# 이 문제는 서버 메모리에 상태를 저장하지 않으므로 워커 2개로 동시 검증을 처리한다.
# 검증 한 번에 수 초가 걸리므로 timeout 을 60초로 둔다.
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--worker-class", "sync", \
     "--timeout", "60", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
