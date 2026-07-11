"""
checks/directory_traversal.py
------------------------------
경로 조작(Directory/Path Traversal) 탐지.

동작 방식은 sql_injection.py와 동일한 패턴: 쿼리 파라미터에 payload를 넣고
응답에 시스템 파일 노출 시그니처가 있는지 확인.

⚠️ 현재(2주차 시작 시점) Backend에 파일을 읽어오는 엔드포인트
   (예: /download?file=...)가 아직 없어서, 크롤링 결과에 테스트할 쿼리
   파라미터 자체가 없을 수 있습니다. 그 경우 findings는 0건이 정상입니다.

⚙️ Backend가 파일 다운로드/조회 라우트를 추가하면:
   - 해당 라우트의 쿼리 파라미터가 crawler.py에 자동으로 수집되고,
     이 파일은 수정 없이 바로 동작합니다.
   - 파라미터 이름이 file/path 계열이 아니면 PRIORITY_PARAM_NAMES에 추가 (선택,
     없어도 전체 파라미터를 어차피 다 시도함)
   - 실제 응답 형식을 보고 SIGNATURES를 보강하세요 (지금은 /etc/passwd, win.ini
     기준 일반적인 시그니처만 있음)
"""
from __future__ import annotations
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from checks.base import Finding, Severity, make_finding

CHECK_NAME = "directory_traversal"

# 파일/경로 관련일 가능성이 높은 파라미터 이름 (있으면 우선 테스트)
PRIORITY_PARAM_NAMES = {"file", "filename", "path", "filepath", "doc", "download", "page", "name"}

# 응답에 이 문자열이 보이면 시스템 파일이 실제로 노출된 것으로 판단
# TODO(Backend 라우트 확정 후): 실제 응답을 보고 시그니처 보강
SIGNATURES = [
    "root:x:0:0",              # /etc/passwd (Linux)
    "root:*:0:0",
    "[extensions]",             # win.ini (Windows)
    "for 16-bit app support",   # win.ini
]


def _inject_query_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    params[param] = payload
    return urlunparse(parsed._replace(query=urlencode(params)))


def _response_has_traversal_evidence(text: str) -> str | None:
    lowered = text.lower()
    for sig in SIGNATURES:
        if sig.lower() in lowered:
            return sig
    return None


def run(session, page, payloads: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    parsed = urlparse(page.url)
    query_params = dict(parse_qsl(parsed.query))
    if not query_params:
        return findings  # 파일 관련 쿼리 파라미터가 있는 페이지가 아직 없을 수 있음

    # 우선순위 파라미터부터 시도하되, 결국 전체 파라미터를 다 시도
    param_names = sorted(query_params.keys(), key=lambda p: p.lower() not in PRIORITY_PARAM_NAMES)

    for param_name in param_names:
        for payload in payloads:
            test_url = _inject_query_param(page.url, param_name, payload)
            try:
                resp = session.get(test_url, timeout=5)
            except Exception:
                continue

            matched = _response_has_traversal_evidence(resp.text)
            if matched:
                findings.append(make_finding(
                    check_name=CHECK_NAME,
                    url=test_url,
                    parameter=param_name,
                    payload=payload,
                    severity=Severity.HIGH,
                    evidence=f"응답에서 시스템 파일 노출 시그니처 발견: '{matched}'",
                    description="파일 경로 파라미터가 검증 없이 사용되어, 서버 내 임의 파일에 접근할 수 있습니다.",
                ))
                break  # 파라미터당 1건만 기록

    return findings
