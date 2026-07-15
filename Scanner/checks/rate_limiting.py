"""
checks/rate_limiting.py
--------------------------
요청 횟수 제한(Rate Limiting) 누락 탐지. (3주차 추가)

동작 방식:
  로그인 등 민감한 엔드포인트에 짧은 시간 안에 연속 요청을 보내고,
  429(Too Many Requests)/503 또는 Retry-After 헤더 등 어떤 형태로든
  제한이 걸리는지 확인한다. 끝까지 제한이 걸리지 않으면 findings로 기록.

⚠️ 대상 범위를 제한하지 않으면 크롤링된 모든 페이지에 반복 요청을 보내
   서버에 과도한 부하를 줄 수 있다. 그래서 SENSITIVE_PATH_HINTS에 해당하는
   경로(로그인/가입/인증 등)에서만 동작하도록 범위를 제한함.
"""
from __future__ import annotations
import time
from urllib.parse import urlparse

from checks.base import Finding, Severity, make_finding

CHECK_NAME = "missing_rate_limiting"

# 이 문자열이 경로에 포함된 페이지에서만 검사 (민감한 엔드포인트로 범위 제한)
SENSITIVE_PATH_HINTS = ("login", "signin", "signup", "auth")

REQUEST_COUNT = 20  # 짧은 시간 동안 보낼 연속 요청 수
THROTTLE_STATUS_CODES = {429, 503}


def run(session, page, payloads: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    path = urlparse(page.url).path.lower()
    if not any(hint in path for hint in SENSITIVE_PATH_HINTS):
        return findings  # 민감 엔드포인트가 아니면 검사하지 않음 (서버 부하 방지)

    method = "POST" if any(f.method == "POST" for f in page.forms) else "GET"
    dummy_data = {"username": "ratelimit_test", "password": "wrong_password"} if method == "POST" else None

    throttled = False
    statuses = []
    start = time.time()

    for _ in range(REQUEST_COUNT):
        try:
            if method == "POST":
                resp = session.post(page.url, data=dummy_data, timeout=5)
            else:
                resp = session.get(page.url, timeout=5)
        except Exception:
            continue

        statuses.append(resp.status_code)

        if resp.status_code in THROTTLE_STATUS_CODES or resp.headers.get("Retry-After"):
            throttled = True
            break

    elapsed = time.time() - start

    if not throttled and statuses:
        findings.append(make_finding(
            check_name=CHECK_NAME,
            url=page.url,
            parameter=None,
            payload=None,
            severity=Severity.LOW,
            evidence=(
                f"{len(statuses)}회 연속 요청({elapsed:.1f}초)에도 429/503/Retry-After 등 "
                f"제한 응답 없음 (응답코드: {sorted(set(statuses))})"
            ),
            description="요청 횟수 제한이 없어 무차별 대입 공격이나 서비스 거부(DoS) 공격에 취약할 수 있습니다.",
        ))

    return findings
