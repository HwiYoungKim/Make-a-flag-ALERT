import os
import sys
from flask import Flask, Response, request

app = Flask(__name__)


def load_flag() -> str:
    flag_path = os.environ.get(
        "FLAG_FILE",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "flag.txt"),
    )
    try:
        with open(flag_path, "r", encoding="utf-8") as f:
            value = f.read().strip()
    except OSError as exc:
        sys.exit(f"[FATAL] FLAG 파일을 읽을 수 없습니다: {flag_path} ({exc})")

    if not value:
        sys.exit(f"[FATAL] FLAG 파일이 비어 있습니다: {flag_path}")

    return value


FLAG = load_flag()

def html_response(body: str, status: int = 200) -> Response:
    return Response(body, status=status, content_type="text/html; charset=utf-8")


def error_page(status: int, title: str, message: str) -> Response:
    body = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>{title}</title></head>"
        f"<body><h1>{status} {title}</h1><p>{message}</p>"
        "<p><a href='/'>검색 페이지로 돌아가기</a></p></body></html>"
    )
    return html_response(body, status)

@app.route("/", methods=["GET"])
def index():
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
    res.set_cookie("FLAG", FLAG, path="/", httponly=False, samesite="Lax")
    res.delete_cookie("xss_lab_test_cookie", path="/")
    return res


@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("keyword")

    if keyword is None or keyword == "":
        return error_page(400, "Bad Request", "검색어(keyword)를 입력해 주세요.")

    # HTML5 표준 구조 준수 및 키워드 미이스케이프 출력
    body = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>Search Result</title></head><body>"
        "<h1>Search Result for: %s</h1>"
        "<p><a href='/'>다시 검색</a></p>"
        "</body></html>"
    ) % keyword
    return html_response(body)

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
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    app.run(host=host, port=port, debug=False)
