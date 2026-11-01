# Dockerfile — 20점 Basic Reflected XSS 실습 서버
# 격리된 CTF 실습 환경에서만 사용하세요.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app

# Flask 앱과 실행에 필요한 WSGI 서버 설치
RUN pip install --no-cache-dir Flask gunicorn

# app.py는 Dockerfile과 같은 빌드 컨텍스트에 있어야 합니다.
COPY app.py /app/app.py

# FLAG는 소스코드에 넣지 않고 별도 파일로 주입합니다.
# flag.txt는 이 Dockerfile과 같은 디렉토리에 두고 빌드하되,
# GitHub 등 공개 저장소에는 절대 커밋하지 마세요 (.gitignore에 추가 권장).
COPY flag.txt /app/flag.txt

EXPOSE 8080

# 개발 서버 대신 Gunicorn으로 Flask 애플리케이션 실행
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "app:app"]
