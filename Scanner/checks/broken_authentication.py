"""
checks/broken_authentication.py
----------------------------------
인증/인가(Authentication & Authorization) 취약점 탐지.

check_name/출력 이름은 Report의 mitigation_guide.md 표기에 맞춰 "broken_authentication"
(Broken Authentication)을 사용한다. mitigation_guide.md 표에 별도의 "Authorization" 항목이
없고 "Broken Authentication" 항목이 로그인/세션 관련 인증-인가 취약점을 다루므로 이 이름으로
통일함. 객체 단위 권한 검증 누락은 이미 checks/idor.py가 다루고 있어 중복되지 않도록 범위를 분리함.

검사 항목 (mitigation_guide.md의 "로그인 시도 횟수 제한, 세션 토큰 무작위성 강화, MFA 도입" 기준):
  1. 세션 쿠키 보안 속성(HttpOnly / Secure / SameSite) 누락 여부
  2. 세션 토큰(쿠키 값) 예측 가능성 - 같은 계정으로 여러 번 로그인해서 값 비교
  3. 로그인 실패 횟수 제한(계정 잠금) 여부 - 틀린 비밀번호를 여러 번 시도한 뒤에도
     정상 로그인이 아무 제약 없이 그대로 성공하는지 확인

⚠️ auth.py의 LOGIN_PATH(/login) 페이지에서만 동작 (로그인 페이지가 아니면 검사하지 않음 ->
   계정당 반복 실행 방지).
⚙️ payloads/broken_authentication.txt 형식 (idor.txt와 동일): username:password
   실제 로그인 가능한 테스트 계정이 최소 1개 있어야 검사가 동작함.

⚠️ 계정 공유/잠금 관련 주의:
   payloads/broken_authentication.txt는 idor.txt 계정을 재사용해도 되도록 문서화되어
   있는데, 이 검사의 3번 항목(로그인 실패 횟수 제한 확인)은 의도적으로 비밀번호를
   FAILED_ATTEMPTS번 틀리게 보낸다. Backend에 실제로 잠금 로직이 있다면(정상 케이스)
   이 계정은 검사가 끝난 시점에 일정 시간 잠긴 상태로 남는다.
   idor.py가 같은 계정으로 뒤이어 로그인을 시도하면 그 잠금 때문에 로그인에 실패해
   IDOR 검사가 오작동(미탐)할 수 있다. 이를 막기 위해 검사 마지막에
   _wait_for_unlock_and_restore()로, 잠긴 것으로 보이면 서버의 잠금 유지시간만큼
   대기한 뒤 정상 비밀번호로 한 번 더 로그인해 실패 횟수를 초기화해 둔다.
   (payloads/*.txt 자체는 이미 실제 계정으로 맞춰져 있어 건드리지 않음 — 계정을
   완전히 분리하려면 broken_authentication.txt에 idor.txt와 다른 전용 계정을
   추가하고 이 파일의 accounts[0] 선택 로직은 그대로 두면 된다.)
"""
from __future__ import annotations
import time
from urllib.parse import urlparse

from checks.base import Finding, Severity, make_finding
from auth import LOGIN_PATH, login

CHECK_NAME = "broken_authentication"

FAILED_ATTEMPTS = 5   # 잠금 여부 확인 전에 보낼 "틀린 비밀번호" 시도 횟수
LOGIN_REPEAT = 3      # 세션 토큰 비교를 위해 반복 로그인할 횟수
MIN_TOKEN_LENGTH = 16  # 세션 토큰이 이보다 짧으면 예측/무작위대입에 취약할 가능성이 높다고 판단

# 계정 잠금 확인 후 복구 대기시간(초). 서버의 실제 잠금 유지시간을 모를 수 있으므로
# 여유 있게 잡는다. (idor.py 등 다른 검사가 같은 계정을 이어서 쓸 때 잠긴 채로
# 넘어가는 것을 방지하기 위한 값 — 서버 LOCK_TIME이 이보다 길면 완전히 막지는 못함)
UNLOCK_WAIT_SECONDS = 35


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
    else:
        # 계정 잠금이 정상 작동한 것으로 보임(정상 비밀번호로도 아직 로그인 실패) ->
        # 이 계정이 idor.py 등 다른 검사에서 재사용될 수 있으므로, 잠금이 풀릴 때까지
        # 기다렸다가 정상 비밀번호로 한 번 더 로그인해 실패 횟수를 초기화해 둔다.
        _wait_for_unlock_and_restore(session, page.url, username, password)

    return findings


def _wait_for_unlock_and_restore(session, login_url: str, username: str, password: str) -> None:
    """
    로그인 실패 횟수 제한(잠금) 테스트로 계정이 잠겼을 수 있으므로,
    다른 검사(예: idor.py)가 같은 계정을 이어서 쓸 때 방해받지 않도록
    잠금 유지시간만큼 대기한 뒤 정상 비밀번호로 한 번 더 로그인해 상태를 복구한다.
    (서버 쪽 실패 횟수 초기화는 보통 로그인 성공 시 이루어짐)
    """
    time.sleep(UNLOCK_WAIT_SECONDS)
    try:
        session.post(login_url, data={"username": username, "password": password}, timeout=5)
    except Exception:
        pass  # 복구 실패는 조용히 무시 — 다음 검사가 로그인 실패로 스스로 감지함
