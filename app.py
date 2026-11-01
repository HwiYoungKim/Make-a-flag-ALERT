"""
app.py - 20점 Basic Reflected XSS 문제 서버 (Flask + Playwright)

!! 경고 !!
교육/CTF 실습용으로 "의도적으로" Reflected XSS 취약점을 가진 서버다.
격리된 환경에서만 실행하고, 공개 웹서비스로 배포하지 말 것.

문제 흐름:
  1) GET /                      : 검색 폼
  2) GET /search?keyword=...    : keyword 를 이스케이프 없이 출력 (의도된 Reflected XSS)
                                  페이지 <head> 의 훅 스크립트가 window.alert 를 감싸서,
                                  alert 창을 닫으면 같은 keyword 로 POST /flag 를 보낸다.
  3) POST /flag (keyword)       : 서버가 그 keyword 의 검색 결과 페이지를 headless Chromium 에서
                                  다시 실행해 alert 대화상자가 실제로 뜨는지 확인한다.
                                  확인되면 FLAG 화면, 아니면 실패 화면을 보여 준다.

이전 버전의 설계 오류와 수정 내용:
  - 이전: "/" 접속 시 FLAG 를 쿠키(httponly=False)로 내려줘서 XSS 없이도 개발자 도구로 확인 가능.
  - 수정: FLAG 는 브라우저로 미리 보내지 않는다. 서버가 alert 를 직접 확인한 뒤에만 응답에 넣는다.
          예전 버전에서 남은 FLAG 쿠키는 "/" 접속 시 삭제한다.

우회 방지:
  - /flag 를 직접 호출하거나 개발자 도구 콘솔에서 alert() 를 불러도,
    서버 재검증에서는 keyword 자체가 alert 를 띄우지 않으므로 FLAG 가 나오지 않는다.
  - 재검증 페이지에는 훅 스크립트와 FLAG 가 없고, 모든 네트워크 요청은 차단된다.
  - 서버는 자기 자신에게 HTTP 요청을 보내지 않는다 (page.set_content 사용).

FLAG 설정 (둘 중 하나, 환경변수 우선):
  - 환경변수 CTF_FLAG
  - 환경변수 FLAG_FILE 이 가리키는 파일 (예: 배포 시스템이 마운트한 파일)
  둘 다 없으면 서버는 시작하지 않는다.
"""

import html
import os
import sys

from flask import Flask, Response, request
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

# ---------------------------------------------------------------------------
# 설정
# ---------------------------------------------------------------------------
MAX_KEYWORD_LENGTH = 2000      # /flag 재검증 대상 keyword 최대 길이
MAX_REQUEST_BYTES = 16 * 1024  # 요청 본문 최대 크기

VERIFY_LOAD_TIMEOUT_MS = 5000  # 재검증 페이지 로드 최대 대기
VERIFY_WAIT_MS = 2000          # 로드 후 alert 를 기다리는 시간
CHROMIUM_SANDBOX = os.environ.get("CHROMIUM_SANDBOX", "1") != "0"


def load_flag() -> str:
    value = os.environ.get("CTF_FLAG", "").strip()
    if value:
        return value

    flag_path = os.environ.get("FLAG_FILE", "").strip()
    if flag_path:
        try:
            with open(flag_path, "r", encoding="utf-8") as f:
                value = f.read().strip()
        except OSError as exc:
            sys.exit(f"[FATAL] FLAG 파일을 읽을 수 없습니다: {flag_path} ({exc})")
        if value:
            return value
        sys.exit(f"[FATAL] FLAG 파일이 비어 있습니다: {flag_path}")

    sys.exit("[FATAL] CTF_FLAG 환경변수(또는 FLAG_FILE)가 설정되지 않았습니다.")


FLAG = load_flag()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES


# ---------------------------------------------------------------------------
# HTML 조각
# ---------------------------------------------------------------------------
# 검색 결과 페이지 <head> 에 들어가는 훅. 사용자 입력은 전혀 포함하지 않는다.
# keyword 는 서버가 끼워 넣지 않고 브라우저가 location.search 에서 직접 읽는다.
ALERT_HOOK = """<script>
(function () {
  var nativeAlert = window.alert;
  var sent = false;
  function goFlag() {
    if (sent) return;
    sent = true;
    var kw = new URLSearchParams(location.search).get('keyword') || '';
    var f = document.createElement('form');
    f.method = 'POST';
    f.action = '/flag';
    var i = document.createElement('input');
    i.type = 'hidden';
    i.name = 'keyword';
    i.value = kw;
    f.appendChild(i);
    (document.body || document.documentElement).appendChild(f);
    HTMLFormElement.prototype.submit.call(f);
  }
  window.alert = function () {
    try { return nativeAlert.apply(window, arguments); }
    finally { setTimeout(goFlag, 0); }
  };
})();
</script>"""

STYLE = (
    "<style>body{font-family:sans-serif;max-width:760px;margin:2em auto;padding:0 1em}"
    "code{background:#f2f2f2;padding:.2em .4em;border-radius:4px}"
    ".flag{font-size:1.4em;color:#1a7f37}.fail{color:#b42318}</style>"
)


def html_response(body: str, status: int = 200) -> Response:
    return Response(body, status=status, content_type="text/html; charset=utf-8")


def error_page(status: int, title: str, message: str) -> Response:
    body = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>{title}</title>{STYLE}</head>"
        f"<body><h1>{status} {title}</h1><p>{message}</p>"
        "<p><a href='/'>검색 페이지로 돌아가기</a></p></body></html>"
    )
    return html_response(body, status)


def build_search_page(keyword: str, with_hook: bool) -> str:
    """
    [의도된 취약점 - VULNERABLE BY DESIGN]
    keyword 를 이스케이프하지 않고 그대로 HTML 본문에 넣는다.
    with_hook=False 는 서버 재검증용: 훅/재시도 버튼 없이 순수한 결과 페이지만 만든다.
    """
    head = "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Search Result</title>"
    if with_hook:
        head += ALERT_HOOK
    body = (
        "</head><body>"
        "<h1>Search Result for: " + keyword + "</h1>"   # <- 취약 지점
        "<p><a href='/'>다시 검색</a></p>"
    )
    if with_hook:
        # 훅이 동작하지 않는 경우(예: iframe 안에서 alert)를 위한 수동 확인 버튼.
        # 이 값은 속성 문맥이므로 반드시 이스케이프한다. 재검증은 어차피 서버가 한다.
        body += (
            "<form action='/flag' method='POST'>"
            "<input type='hidden' name='keyword' value=\"" + html.escape(keyword, quote=True) + "\">"
            "<button type='submit'>alert 를 띄웠다면: FLAG 확인</button>"
            "</form>"
        )
    return head + body + "</body></html>"


# ---------------------------------------------------------------------------
# 서버 측 alert 재검증
# ---------------------------------------------------------------------------
def alert_fired(page_html: str) -> bool:
    fired = False

    def on_dialog(dialog):
        nonlocal fired
        if dialog.type == "alert":
            fired = True
        try:
            dialog.dismiss()
        except PlaywrightError:
            pass

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, chromium_sandbox=CHROMIUM_SANDBOX)
        try:
            context = browser.new_context()
            context.route("**/*", lambda route: route.abort())  # 모든 네트워크 차단
            page = context.new_page()
            page.on("dialog", on_dialog)
            try:
                page.set_content(page_html, wait_until="load", timeout=VERIFY_LOAD_TIMEOUT_MS)
            except PlaywrightError:
                pass
            if not fired:
                try:
                    page.wait_for_timeout(VERIFY_WAIT_MS)
                except PlaywrightError:
                    pass
        finally:
            browser.close()
    return fired


# ---------------------------------------------------------------------------
# 라우트
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    body = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>Search</title>{STYLE}</head><body>"
        "<h1>Search</h1>"
        "<form action='/search' method='GET'>"
        "<input type='text' name='keyword' placeholder='검색어 입력' autofocus>"
        "<button type='submit'>검색</button>"
        "</form>"
        "<p>검색 결과 페이지에서 alert 창을 띄우면 FLAG 를 얻을 수 있습니다.</p>"
        "</body></html>"
    )
    res = html_response(body)
    # 이전 버전이 남긴 FLAG 쿠키 정리 (새 버전은 FLAG 쿠키를 만들지 않는다)
    res.delete_cookie("FLAG", path="/")
    return res


@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("keyword")
    if keyword is None or keyword == "":
        return error_page(400, "Bad Request", "검색어(keyword)를 입력해 주세요.")
    return html_response(build_search_page(keyword, with_hook=True))


@app.route("/flag", methods=["POST"])
def flag():
    keyword = request.form.get("keyword", "")
    if keyword == "":
        return error_page(400, "Bad Request", "검색어(keyword)가 없습니다.")
    if len(keyword) > MAX_KEYWORD_LENGTH:
        return error_page(400, "Bad Request", "검색어가 너무 깁니다.")

    try:
        ok = alert_fired(build_search_page(keyword, with_hook=False))
    except Exception:
        app.logger.exception("verification failed")
        return error_page(500, "Internal Server Error", "검증 중 오류가 발생했습니다.")

    if not ok:
        body = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>Fail</title>{STYLE}</head><body>"
            "<h1 class='fail'>alert 가 확인되지 않았습니다</h1>"
            "<p>검색어(keyword) 자체로 alert 창이 떠야 합니다.</p>"
            "<p><a href='/'>다시 시도</a></p></body></html>"
        )
        return html_response(body, 200)

    body = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>FLAG</title>{STYLE}</head><body>"
        "<h1>alert 확인 완료!</h1>"
        "<p>FLAG:</p>"
        f"<p class='flag'><code>{html.escape(FLAG)}</code></p>"
        "<p><a href='/'>처음으로</a></p></body></html>"
    )
    res = html_response(body, 200)
    res.headers["Cache-Control"] = "no-store"
    return res


# ---------------------------------------------------------------------------
# 오류 처리
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(_e):
    return error_page(404, "Not Found", "요청한 페이지를 찾을 수 없습니다.")


@app.errorhandler(405)
def method_not_allowed(_e):
    return error_page(405, "Method Not Allowed", "허용되지 않는 요청 방식입니다.")


@app.errorhandler(413)
def payload_too_large(_e):
    return error_page(413, "Payload Too Large", "요청이 너무 큽니다.")


@app.errorhandler(500)
def server_error(_e):
    return error_page(500, "Internal Server Error", "서버 내부 오류가 발생했습니다.")


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    app.run(host=host, port=port, debug=False)
