"""
checks/rate_limiting.py
--------------------------
요청 횟수 제한(Rate Limiting) 누락 탐지.

동작 방식:
  민감한 엔드포인트에 짧은 시간 안에 연속 요청을 보내고,
  429(Too Many Requests)/503 또는 Retry-After 헤더 등 어떤 형태로든
  제한이 걸리는지 확인한다. 끝까지 제한이 걸리지 않으면 findings로 기록.

⚠️ 검사 대상을 /vuln/rate-limit로만 제한하는 이유:
   이 프로젝트 Backend는 로그인 관련 두 엔드포인트를 명확히 분리해 구현했다.
     - /login: 실제로 로그인 실패 횟수 제한(계정 잠금)이 구현돼 있음. 다만 그 방식이
       429/503/Retry-After가 아니라 HTTP 200 + "로그인 시도 횟수를 초과했습니다" 문구다.
       이 검사가 429/503/Retry-After만 "제한됨"으로 인식하는 범용 판정 로직이라, /login을
       검사 대상에 포함하면 실제로는 정상적으로 제한 중인데도 오탐(missing rate limiting)이
       난다. (/login의 이 잠금 로직 자체는 checks/broken_authentication.py의 3번 항목이
       이미 별도로 검증하고 있으므로, 여기서 /login까지 다시 볼 필요도 없음 — 중복 방지.)
     - /vuln/rate-limit: 요청 횟수 제한이 전혀 없도록 의도적으로 구현됨. 이 검사의
       실제 대상은 사실상 이 엔드포인트 하나뿐이다.
   이 스캐너는 범용 웹 취약점 스캐너가 아니라 이 Backend 전용이므로, "200 + 특정 문구도
   제한으로 인식"하는 범용 판정 로직을 새로 만드는 대신 검사 범위 자체를 명확한 취약
   엔드포인트로 좁혔다.
"""
from __future__ import annotations
import time
from urllib.parse import urlparse

from checks.base import Finding, Severity, make_finding

CHECK_NAME = "missing_rate_limiting"

# 이 프로젝트에서 rate limiting 미비가 의도적으로 구현된 엔드포인트는 이것 하나뿐.
TARGET_PATH = "/vuln/rate-limit"

REQUEST_COUNT = 20  # 짧은 시간 동안 보낼 연속 요청 수
THROTTLE_STATUS_CODES = {429, 503}


def run(session, page, payloads: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    path = urlparse(page.url).path.rstrip("/")
    if path != TARGET_PATH:
        return findings  # /vuln/rate-limit이 아니면 검사 대상 아님 (모듈 docstring 참고)

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
