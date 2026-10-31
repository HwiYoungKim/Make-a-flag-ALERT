"""
app.py - 20점 Basic Reflected XSS 실습 문제 서버 (Flask)

교육/CTF 실습용으로 의도된 Reflected XSS 취약점이 포함되어 있습니다.
개선사항 적용 완료:
 1. Response Header charset=utf-8 명시
 2. 실습 유효성을 위한 메인 페이지 접속 시 테스트 쿠키(session_id) 발급
 3. HTML5 표준 규격(DOCTYPE, head, charset) 적용
 4. Docker 컨테이너 바인딩 지원을 위한 기본 HOST=0.0.0.0 설정
"""

import os
from flask import Flask, Response, request

app = Flask(__name__)


# ---------------------------------------------------------------------------
# 공통 헬퍼
# ---------------------------------------------------------------------------
def html_response(body: str, status: int = 200) -> Response:
    """HTML 응답 생성 (UTF-8 인코딩 명시)"""
    return Response(body, status=status, content_type="text/html; charset=utf-8")


def error_page(status: int, title: str, message: str) -> Response:
    """일반 오류 처리 페이지 (입력값 미반영으로 secondary XSS 방지)"""
    body = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>{title}</title></head>"
        f"<body><h1>{status} {title}</h1><p>{message}</p>"
        "<p><a href='/'>검색 페이지로 돌아가기</a></p></body></html>"
    )
    return html_response(body, status)


# ---------------------------------------------------------------------------
# 라우트
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    """
    진입 페이지: 검색어 입력 폼.
    실습 편의를 위해 접속 시 테스트용 세션 쿠키를 발급합니다.
    """
    body = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>Search</title></head><body>"
        "<h1>Search</h1>"
        "<form action='/search' method='GET'>"
        "<input type='text' name='keyword' placeholder='검색어 입력' autofocus>"
        "<button type='submit'>검색</button>"
        "</form></body></html>"
    )
    res = html_response(body)
    # 격리된 CTF 실습 전용 더미 쿠키입니다. 실제 인증/세션 토큰으로 사용하지 마세요.
    # JavaScript 접근 실습을 위해 HttpOnly=False로 설정합니다.
    res.set_cookie(
        "xss_lab_test_cookie",
        "dummy_guest_token_12345",
        httponly=False,
        secure=os.environ.get("COOKIE_SECURE", "0") == "1",
        samesite="Lax",
        path="/",
    )
    return res


@app.route("/search", methods=["GET"])
def search():
    """
    검색 엔드포인트

    [의도된 취약 동작]
      keyword를 이스케이프/인코딩/필터링 없이 HTML 문자열에 그대로 삽입합니다. -> Reflected XSS
    """
    keyword = request.args.get("keyword")

    # 일반 오류 처리: 파라미터 누락 / 빈 값
    if keyword is None or keyword == "":
        return error_page(400, "Bad Request", "검색어(keyword)를 입력해 주세요.")

    # ----- 의도된 취약 지점 (VULNERABLE BY DESIGN) -----
    # HTML5 표준 구조 준수 및 키워드 미이스케이프 출력
    body = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>Search Result</title></head><body>"
        "<h1>Search Result for: %s</h1>"
        "<p><a href='/'>다시 검색</a></p>"
        "</body></html>"
    ) % keyword
    # ---------------------------------------------------
    return html_response(body)


# ---------------------------------------------------------------------------
# 일반 HTTP 오류 처리
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(_e):
    return error_page(404, "Not Found", "요청한 페이지를 찾을 수 없습니다.")


@app.errorhandler(405)
def method_not_allowed(_e):
    return error_page(405, "Method Not Allowed", "허용되지 않는 요청 방식입니다. (GET만 지원)")


@app.errorhandler(500)
def server_error(_e):
    return error_page(500, "Internal Server Error", "서버 내부 오류가 발생했습니다.")


if __name__ == "__main__":
    # 0.0.0.0은 컨테이너의 네트워크 인터페이스에서 요청을 수신하도록 합니다.
    # 외부 접속을 위해서는 실행 환경의 포트 공개/매핑도 별도로 설정해야 합니다.
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    app.run(host=host, port=port, debug=False)
