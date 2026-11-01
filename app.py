"""
app.py - 40점 Filtered Stored XSS 문제 서버 (Flask + Jinja2 + Playwright)

!! 경고 !!
이 서버는 교육/CTF 실습용으로 "의도적으로" Stored XSS 취약점을 가지고 있다.
반드시 격리된 환경에서만 실행하고, 공개 웹서비스에 배포하지 말 것.

동작 흐름:
  1) POST /comment       : 댓글 저장 (<script> 단순 필터, 최대 1000자, 최대 100개 FIFO)
  2) GET  /board         : 댓글을 {{ body | safe }} 로 출력 -> 의도된 Stored XSS
  3) POST /verify/<id>   : 해당 댓글 하나만 렌더링한 HTML 을 headless Chromium 에
                           page.set_content() 로 넣고, alert 대화상자가 뜨면
                           환경변수 CTF_FLAG 값을 text/plain 으로 반환한다.

플래그 취급:
  - 플래그는 오직 서버 프로세스의 환경변수 CTF_FLAG 에만 존재한다.
  - Dockerfile / 이미지 / 쿠키 / 브라우저 페이지 어디에도 넣지 않는다.
  - CTF_FLAG 가 없으면 /verify 는 500 을 반환한다 (플래그 노출 없음).

검증 브라우저 격리:
  - 서버 자신에게 HTTP 요청을 보내지 않는다 (단일 sync 워커 교착 방지).
  - 모든 네트워크 요청은 route 로 차단한다 (외부 전송 불가).
  - Chromium 샌드박스를 켠 상태로 실행한다 (CHROMIUM_SANDBOX=1 기본값).

단일 프로세스 전제:
  댓글을 프로세스 메모리에 저장하므로 gunicorn 은 --workers 1 --worker-class sync 로 실행한다.
  서버를 재시작하면 댓글은 모두 초기화된다. (정상 동작)
"""

import itertools
import os

from flask import Flask, Response, redirect, render_template, request, url_for
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

# ---------------------------------------------------------------------------
# 설정
# ---------------------------------------------------------------------------
MAX_COMMENT_LENGTH = 1000      # 댓글당 최대 길이 (문자 수)
MAX_COMMENTS = 100             # 최대 저장 댓글 수 (초과 시 FIFO)
MAX_REQUEST_BYTES = 16 * 1024  # 요청 본문 최대 16 KiB (초과 시 413)

VERIFY_LOAD_TIMEOUT_MS = 5000  # set_content 최대 대기
VERIFY_WAIT_MS = 2000          # 로드 후 alert 를 기다리는 시간
CHROMIUM_SANDBOX = os.environ.get("CHROMIUM_SANDBOX", "1") != "0"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES

# 댓글 저장소: {"id": int, "body": str, "verified": None | bool}
COMMENTS = []
_id_counter = itertools.count(1)


# ---------------------------------------------------------------------------
# 헬퍼
# ---------------------------------------------------------------------------
def plain_error(message: str, status: int) -> Response:
    """고정 메시지 text/plain 응답. 사용자 입력은 포함하지 않는다."""
    return Response(message, status=status, mimetype="text/plain")


def contains_script_tag(comment: str) -> bool:
    """
    단순 문자열 필터: "<script>" 포함 여부를 대소문자 구분 없이 검사한다.
    <img onerror>, <svg onload> 등은 막지 못한다. (의도된 학습 포인트)
    """
    return "<script>" in comment.lower()


def find_comment(comment_id: int):
    return next((c for c in COMMENTS if c["id"] == comment_id), None)


def alert_fired(html: str) -> bool:
    """
    렌더링된 HTML 을 headless Chromium 에 직접 넣고, alert 대화상자가 떴는지 확인한다.
    - 페이지에는 플래그/쿠키가 전혀 없다.
    - 모든 네트워크 요청은 차단된다.
    """
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
            context.route("**/*", lambda route: route.abort())  # 외부/내부 네트워크 전부 차단
            page = context.new_page()
            page.on("dialog", on_dialog)
            try:
                page.set_content(html, wait_until="load", timeout=VERIFY_LOAD_TIMEOUT_MS)
            except PlaywrightError:
                pass  # 로드 지연/오류여도 그 사이 alert 가 떴을 수 있으므로 계속 진행
            if not fired:
                try:
                    page.wait_for_timeout(VERIFY_WAIT_MS)
                except PlaywrightError:
                    pass  # 페이지가 스스로 닫히는 등의 경우
        finally:
            browser.close()
    return fired


# ---------------------------------------------------------------------------
# 라우트
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("board"))


@app.route("/board", methods=["GET"])
def board():
    return render_template("board.html", comments=COMMENTS, verify_mode=False)


@app.route("/comment", methods=["POST"])
def add_comment():
    # 1) Content-Type
    if request.mimetype != "application/x-www-form-urlencoded":
        return plain_error("Unsupported Media Type: use application/x-www-form-urlencoded.", 415)

    comment = request.form.get("comment")

    # 2) 누락/공백
    if comment is None or comment.strip() == "":
        return plain_error("Invalid input: comment is required.", 400)

    # 3) 길이
    if len(comment) > MAX_COMMENT_LENGTH:
        return plain_error("Invalid input: comment is too long.", 400)

    # 4) 단순 필터
    if contains_script_tag(comment):
        return plain_error("Invalid input: script tag is not allowed.", 400)

    # 5) FIFO 후 저장 (원본 그대로)
    while len(COMMENTS) >= MAX_COMMENTS:
        COMMENTS.pop(0)
    COMMENTS.append({"id": next(_id_counter), "body": comment, "verified": None})

    # 6) PRG
    return redirect(url_for("board"), code=303)


@app.route("/verify/<int:comment_id>", methods=["POST"])
def verify(comment_id: int):
    target = find_comment(comment_id)
    if target is None:
        return plain_error("Not Found.", 404)

    flag = os.environ.get("CTF_FLAG")
    if not flag:
        return plain_error("Server misconfigured.", 500)

    # 대상 댓글 하나만, 폼/버튼 없이 렌더링 (내부 HTTP 요청 없음)
    html = render_template("board.html", comments=[target], verify_mode=True)

    try:
        ok = alert_fired(html)
    except Exception:  # 브라우저 기동 실패 등
        app.logger.exception("verification failed")
        return plain_error("Verification failed.", 500)

    target["verified"] = ok
    if ok:
        return Response(flag, status=200, mimetype="text/plain")
    return plain_error("No alert detected.", 200)


# ---------------------------------------------------------------------------
# 일반 HTTP 오류 처리 (고정 메시지)
# ---------------------------------------------------------------------------
@app.errorhandler(400)
def bad_request(_e):
    return plain_error("Bad Request.", 400)


@app.errorhandler(404)
def not_found(_e):
    return plain_error("Not Found.", 404)


@app.errorhandler(405)
def method_not_allowed(_e):
    return plain_error("Method Not Allowed.", 405)


@app.errorhandler(413)
def payload_too_large(_e):
    return plain_error("Payload Too Large.", 413)


@app.errorhandler(500)
def internal_error(_e):
    return plain_error("Internal Server Error.", 500)


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=False)
