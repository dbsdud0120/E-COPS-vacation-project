"""
checks/broken_authentication.py
----------------------------------
인증/인가(Authentication & Authorization) 취약점 탐지. (3주차 추가)

check_name/출력 이름은 Report의 mitigation_guide.md 표기에 맞춰 "broken_authentication"
(Broken Authentication)을 사용한다. (Notion 3주차 요청의 "Authorization 취약점 검사"에 대응 —
mitigation_guide.md 표에 별도의 "Authorization" 항목이 없고 "Broken Authentication" 항목이
로그인/세션 관련 인증-인가 취약점을 다루므로 이 이름으로 통일함. 객체 단위 권한 검증 누락은
이미 checks/idor.py가 다루고 있어 중복되지 않도록 범위를 분리함.)

검사 항목 (mitigation_guide.md의 "로그인 시도 횟수 제한, 세션 토큰 무작위성 강화, MFA 도입" 기준):
  1. 세션 쿠키 보안 속성(HttpOnly / Secure / SameSite) 누락 여부
  2. 세션 토큰(쿠키 값) 예측 가능성 - 같은 계정으로 여러 번 로그인해서 값 비교
  3. 로그인 실패 횟수 제한(계정 잠금) 여부 - 틀린 비밀번호를 여러 번 시도한 뒤에도
     정상 로그인이 아무 제약 없이 그대로 성공하는지 확인

⚠️ auth.py의 LOGIN_PATH(/login) 페이지에서만 동작 (로그인 페이지가 아니면 검사하지 않음 ->
   계정당 반복 실행 방지).
⚙️ payloads/broken_authentication.txt 형식 (idor.txt와 동일): username:password
   실제 로그인 가능한 테스트 계정이 최소 1개 있어야 검사가 동작함.
"""
from __future__ import annotations
from urllib.parse import urlparse

from checks.base import Finding, Severity, make_finding
from auth import LOGIN_PATH, login

CHECK_NAME = "broken_authentication"

FAILED_ATTEMPTS = 5   # 잠금 여부 확인 전에 보낼 "틀린 비밀번호" 시도 횟수
LOGIN_REPEAT = 3      # 세션 토큰 비교를 위해 반복 로그인할 횟수
MIN_TOKEN_LENGTH = 16  # 세션 토큰이 이보다 짧으면 예측/무작위대입에 취약할 가능성이 높다고 판단


def _parse_accounts(payloads: list[str]) -> list[tuple[str, str]]:
    accounts = []
    for line in payloads:
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        username, _, password = line.partition(":")
        accounts.append((username.strip(), password.strip()))
    return accounts


def _session_cookie_flags(resp) -> list[str]:
    """Set-Cookie 헤더 원문에서 HttpOnly/Secure/SameSite 플래그 누락 여부 확인."""
    try:
        raw_cookies = resp.raw.headers.get_all("Set-Cookie") or []
    except Exception:
        single = resp.headers.get("Set-Cookie")
        raw_cookies = [single] if single else []

    if not raw_cookies:
        return []

    combined = " ".join(raw_cookies).lower()
    missing = []
    if "httponly" not in combined:
        missing.append("HttpOnly")
    if "secure" not in combined:
        missing.append("Secure")
    if "samesite" not in combined:
        missing.append("SameSite")
    return missing


def run(session, page, payloads: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    if urlparse(page.url).path.rstrip("/") != LOGIN_PATH:
        return findings  # 로그인 페이지가 아니면 검사 대상 아님

    accounts = _parse_accounts(payloads)
    if not accounts:
        return findings  # 테스트 계정 없음 (payloads/broken_authentication.txt 확인)

    username, password = accounts[0]
    parsed = urlparse(page.url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # 1) 로그인 성공 시 세션 쿠키 보안 속성 확인
    try:
        login_resp = session.post(
            page.url, data={"username": username, "password": password}, timeout=5
        )
    except Exception:
        login_resp = None

    if login_resp is not None:
        missing_flags = _session_cookie_flags(login_resp)
        if missing_flags:
            findings.append(make_finding(
                check_name=CHECK_NAME,
                url=page.url,
                parameter="Set-Cookie",
                payload=None,
                severity=Severity.MEDIUM,
                evidence=f"세션 쿠키에 {', '.join(missing_flags)} 속성이 없음",
                description=(
                    "세션 쿠키 보안 속성이 없으면 XSS를 통한 쿠키 탈취(HttpOnly 누락), "
                    "평문 전송(Secure 누락), CSRF(SameSite 누락) 위험이 높아집니다."
                ),
            ))

    # 2) 세션 토큰 예측 가능성: 같은 계정으로 여러 번 로그인해서 토큰 값을 비교
    tokens = []
    for _ in range(LOGIN_REPEAT):
        s = login(base_url, username, password)
        if s is None:
            continue
        cookie_value = s.cookies.get("session")
        if cookie_value:
            tokens.append(cookie_value)

    if len(tokens) >= 2:
        short_tokens = [t for t in tokens if len(t) < MIN_TOKEN_LENGTH]
        if short_tokens:
            findings.append(make_finding(
                check_name=CHECK_NAME,
                url=page.url,
                parameter="session",
                payload=None,
                severity=Severity.HIGH,
                evidence=f"세션 토큰 길이가 {MIN_TOKEN_LENGTH}자 미만으로 짧음 (예시: {short_tokens[0][:20]}...)",
                description="세션 토큰이 짧거나 예측 가능한 패턴이면 무작위 대입으로 세션을 탈취당할 수 있습니다.",
            ))
        elif len(set(tokens)) == 1:
            findings.append(make_finding(
                check_name=CHECK_NAME,
                url=page.url,
                parameter="session",
                payload=None,
                severity=Severity.HIGH,
                evidence="같은 계정으로 여러 번 로그인해도 세션 토큰이 매번 동일함",
                description="세션 토큰이 매 로그인마다 갱신되지 않으면 세션 고정(Session Fixation) 공격에 취약합니다.",
            ))

    # 3) 로그인 실패 횟수 제한(계정 잠금) 여부
    for _ in range(FAILED_ATTEMPTS):
        try:
            session.post(
                page.url,
                data={"username": username, "password": password + "_wrong"},
                timeout=5,
            )
        except Exception:
            break

    try:
        retry_resp = session.post(
            page.url, data={"username": username, "password": password}, timeout=5
        )
    except Exception:
        retry_resp = None

    if retry_resp is not None and "성공" in retry_resp.text:
        findings.append(make_finding(
            check_name=CHECK_NAME,
            url=page.url,
            parameter="username",
            payload=None,
            severity=Severity.CRITICAL,
            evidence=f"비밀번호 {FAILED_ATTEMPTS}회 연속 실패 후에도 정상 로그인이 제한 없이 성공함",
            description="로그인 실패 횟수 제한(계정 잠금)이 없어 무차별 대입(Brute Force) 공격에 취약합니다.",
        ))

    return findings
