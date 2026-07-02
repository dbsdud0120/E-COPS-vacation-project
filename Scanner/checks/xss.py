"""
checks/xss.py
--------------
가장 기본적인 "반사형(Reflected) XSS" 탐지 틀.

동작 방식(MVP):
  1. 쿼리 파라미터에 고유 마커가 포함된 payload를 삽입해 요청
  2. 응답 HTML에 payload가 "이스케이프 없이" 그대로 반사되는지 확인
  3. 그대로 반사되면 Finding 생성

주의:
  - 단순 문자열 포함 여부만 체크하는 매우 기초적인 방식이다.
  - 다음 주차에 취약 서버가 준비되면:
      a) BeautifulSoup으로 실제 <script> 컨텍스트/속성 컨텍스트 반사 여부 구분
      b) DOM 기반 XSS는 별도 headless 브라우저(Playwright) 검사로 분리
      c) 저장형(Stored) XSS는 "제출 후 다른 페이지 재방문" 시나리오로 별도 구현
"""

from __future__ import annotations
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from checks.base import Finding, Severity, make_finding

CHECK_NAME = "xss"


def _inject_query_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    params[param] = payload
    new_query = urlencode(params)
    return urlunparse(parsed._replace(query=new_query))


def _is_reflected_unescaped(response_text: str, payload: str) -> bool:
    """payload 원문이 이스케이프(예: &lt;) 없이 그대로 응답에 포함되는지 확인"""
    return payload in response_text


def run(session, page, payloads: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    parsed = urlparse(page.url)
    query_params = dict(parse_qsl(parsed.query))

    # 1) URL 쿼리 파라미터 검사
    for param_name in query_params:
        for payload in payloads:
            test_url = _inject_query_param(page.url, param_name, payload)
            try:
                resp = session.get(test_url, timeout=5)
            except Exception:
                continue

            if _is_reflected_unescaped(resp.text, payload):
                findings.append(make_finding(
                    check_name=CHECK_NAME,
                    url=test_url,
                    parameter=param_name,
                    payload=payload,
                    severity=Severity.MEDIUM,
                    evidence="입력한 payload가 이스케이프 없이 응답에 그대로 반사됨",
                    description="입력값이 HTML에 그대로 출력되어 반사형 XSS로 이어질 가능성이 있습니다.",
                ))
                break

    # 2) form input 검사 (틀만 작성)
    # TODO(다음 주차): 실제 POST 전송 + 응답 페이지에서 반사 여부 확인
    for form in page.forms:
        for input_name in form.inputs:
            findings.append(make_finding(
                check_name=CHECK_NAME,
                url=form.action,
                parameter=input_name,
                payload=None,
                severity=Severity.INFO,
                evidence="form 필드 발견 (실제 XSS 전송 로직은 미구현)",
                description="다음 주차에 form 기반 XSS 페이로드 전송 로직을 추가할 예정입니다.",
            ))

    return findings
