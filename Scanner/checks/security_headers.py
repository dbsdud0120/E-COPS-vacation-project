"""
checks/security_headers.py
---------------------------
응답 HTTP 헤더에 권장 보안 헤더가 빠져 있는지 확인.

다른 3개 검사와 달리 Backend의 추가 구현이 필요 없어서 지금 바로 동작합니다.
(로그인도, 특정 엔드포인트도 필요 없음 — 크롤링된 모든 페이지에 대해 헤더만 확인)
"""
from __future__ import annotations

from checks.base import Finding, Severity, make_finding

CHECK_NAME = "security_headers"

# 헤더명 -> (없을 때 severity, 설명)
# 기준: OWASP Secure Headers Project 권장 목록
REQUIRED_HEADERS = {
    "Content-Security-Policy": (
        Severity.MEDIUM,
        "CSP가 없으면 XSS 등으로 삽입된 악성 스크립트 실행을 브라우저 단에서 막을 방법이 없습니다.",
    ),
    "X-Frame-Options": (
        Severity.MEDIUM,
        "클릭재킹(Clickjacking) 공격에 노출될 수 있습니다.",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "MIME 스니핑으로 인한 콘텐츠 타입 혼동 공격에 노출될 수 있습니다.",
    ),
    "Strict-Transport-Security": (
        Severity.LOW,
        "HTTPS 강제가 안 되어 있어 다운그레이드/중간자 공격 위험이 있습니다. (HTTP로만 서비스 중이면 해당 없음)",
    ),
    "Referrer-Policy": (
        Severity.INFO,
        "Referrer 정보가 외부로 과도하게 노출될 수 있습니다.",
    ),
}


def run(session, page, payloads: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    try:
        resp = session.get(page.url, timeout=5)
    except Exception:
        return findings

    headers = resp.headers  # requests.structures.CaseInsensitiveDict (대소문자 무시하고 비교됨)

    for header_name, (severity, description) in REQUIRED_HEADERS.items():
        if header_name not in headers:
            findings.append(make_finding(
                check_name=CHECK_NAME,
                url=page.url,
                parameter=None,
                payload=None,
                severity=severity,
                evidence=f"응답 헤더에 '{header_name}' 없음",
                description=description,
            ))

    return findings
