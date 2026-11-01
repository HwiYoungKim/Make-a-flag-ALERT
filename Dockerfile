# Dockerfile - 40점 Filtered Stored XSS 문제 서버
# 교육용 CTF 전용 이미지입니다.
#
# 플래그는 이미지에 넣지 않습니다. 실행 시 환경변수 CTF_FLAG 로만 주입합니다.
#   docker run -p 8080:8080 --shm-size=256m -e CTF_FLAG='<플래그 값>' <image>

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app

# root 단계: 패키지, Chromium 및 시스템 의존성 설치 (--with-deps 는 root 필요)
RUN pip install --no-cache-dir Flask==3.1.3 gunicorn==23.0.0 playwright==1.63.0 \
    && playwright install --with-deps chromium \
    && chmod -R a+rX /ms-playwright \
    && rm -rf /var/lib/apt/lists/* \
    && adduser --disabled-password --gecos "" appuser

COPY --chown=appuser:appuser app.py /app/app.py
COPY --chown=appuser:appuser templates /app/templates

# Chromium 샌드박스는 root 로 실행되지 않으므로 반드시 일반 사용자로 실행한다.
USER appuser

EXPOSE 8080

# 단일 워커 / sync: 댓글이 프로세스 메모리에 있으므로 필수.
# 검증 한 번에 수 초가 걸리므로 timeout 을 60초로 둔다.
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--worker-class", "sync", \
     "--timeout", "60", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
