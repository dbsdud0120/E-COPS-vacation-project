"""
auth.py
-------
로그인이 필요한 검사(IDOR 등)를 위한 세션 로그인 헬퍼.

Backend/app.py 기준으로 작성됨:
  - POST /login  (form 데이터: username, password)
  - 로그인 성공 시 Flask session 쿠키 발급
  - 로그인 필요 여부 확인용: GET /users (로그인 안 하면 401)

⚙️ Backend의 로그인 스펙이 바뀌면 아래 상수만 고치면 됩니다.
   (다른 파일을 고칠 필요 없음 — checks/idor.py 등이 이 함수를 통해서만 로그인함)
"""
from __future__ import annotations
import requests

LOGIN_PATH = "/login"
USERNAME_FIELD = "username"
PASSWORD_FIELD = "password"

# 로그인 성공 여부를 판단하기 위해 호출할, "로그인해야만 200이 나오는" 엔드포인트
# TODO(Backend 변경 시): 로그인 필요 페이지가 바뀌면 이 값도 같이 수정
AUTH_CHECK_PATH = "/users"


def login(base_url: str, username: str, password: str, timeout: int = 5) -> requests.Session | None:
    """
    지정된 계정으로 로그인해서 세션 쿠키가 담긴 Session 객체를 반환.
    로그인 실패(자격 증명 오류, 네트워크 오류 등) 시 None 반환.
    """
    session = requests.Session()
    login_url = base_url.rstrip("/") + LOGIN_PATH

    try:
        session.post(
            login_url,
            data={USERNAME_FIELD: username, PASSWORD_FIELD: password},
            timeout=timeout,
        )
    except requests.RequestException as e:
        print(f"[auth] 로그인 요청 실패 ({username}): {e}")
        return None

    # 로그인 성공 여부는 "로그인 성공!" 같은 응답 문자열 대신,
    # 인증이 필요한 엔드포인트가 실제로 열리는지로 확인 (문구가 바뀌어도 안 깨지도록)
    check_url = base_url.rstrip("/") + AUTH_CHECK_PATH
    try:
        resp = session.get(check_url, timeout=timeout)
    except requests.RequestException:
        return None

    if resp.status_code == 200:
        return session

    print(f"[auth] 로그인 확인 실패 ({username}): {AUTH_CHECK_PATH} -> {resp.status_code}")
    return None
