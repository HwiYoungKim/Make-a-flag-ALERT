# Make-a-flag-ALERT (20점 Basic Reflected XSS)

검색 결과 페이지(`/search?keyword=...`)에서 `alert` 창을 띄우면, 창을 닫는 순간 화면이 FLAG 페이지로 바뀝니다.
서버가 같은 검색어를 headless Chromium 으로 다시 실행해 alert 가 실제로 뜨는지 확인한 뒤에만 FLAG 를 보여 줍니다.

## 실행

```bash
cp .env.example .env      # .env 안의 CTF_FLAG 를 실제 플래그로 수정
docker compose up --build
# http://localhost:8080
```

`docker run` 으로 실행할 때:

```bash
docker build -t xss20 .
docker run -p 8080:8080 --shm-size=256m -e CTF_FLAG='<플래그 값>' xss20
```

플래그를 파일로 넣어야 하는 배포 환경이면 `CTF_FLAG` 대신 `FLAG_FILE=/경로/flag.txt` 를 지정하고 그 파일을 마운트합니다.
`.env`, `flag.txt` 는 저장소에 올리지 않습니다.
