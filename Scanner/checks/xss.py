"""
checks/xss.py
--------------
"반사형(Reflected) XSS"만 담당하는 탐지 틀.

동작 방식:
  1. 크롤링된 페이지 URL의 쿼리 파라미터에 고유 마커가 포함된 payload를 삽입해 요청
  2. 응답 HTML에 payload가 "이스케이프 없이, 실행 가능한 HTML 문맥으로" 그대로
     반사되는지 확인 (checks/xss_context.py의 is_exploitable_reflection())
  3. 그대로 반사되면 Finding 생성

⚠️ 범위 (이 프로젝트의 vulnerable-backend 기준):
   이 check은 GET 쿼리 파라미터 기반 반사형 XSS만 다룬다(예: /vuln/comment?text=...).
   POST form은 다루지 않는다 — 이 Backend에는 "POST 응답에 입력값이 즉시(DB 저장 없이)
   그대로 반사되는" POST form이 없고, 유일하게 입력값을 되돌려 보여주는 POST form인
   /posts는 DB에 저장한 뒤 /vuln/posts에서 출력되는 저장형(Stored) XSS 케이스라
   stored_xss.py가 전담한다. 만약 xss.py가 /posts 같은 form에도 payload마다
   실제로 POST를 보내면, 그 자체로 (취약점 발견 여부와 무관하게) 게시글이 계속
   쌓이는 부작용이 생긴다 — 반사형 검사를 위해 굳이 데이터를 남길 필요는 없으므로
   POST form 검사는 하지 않는다.
   두 check 간 역할 중복(같은 form에 두 번 payload를 제출하는 것)도 이렇게 없앤다.

개선 여지 (이 프로젝트 범위 밖):
  - DOM 기반 XSS는 별도 headless 브라우저(Playwright) 검사로 분리
  - 범용 스캐너로 확장한다면 "저장 없이 즉시 반사되는 POST form"을 별도로
    구분해서 다시 다뤄야 함
"""

from __future__ import annotations
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from checks.base import Finding, Severity, make_finding
from checks.xss_context import is_exploitable_reflection

CHECK_NAME = "xss"


def _inject_query_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    params[param] = payload
    new_query = urlencode(params)
    return urlunparse(parsed._replace(query=new_query))


def _is_reflected_unescaped(response, payload: str) -> bool:
    """payload 원문이 이스케이프 없이, 그리고 실제로 실행 가능한 HTML 문맥에
    반영되어 응답에 포함되는지 확인. (단순 substring 매칭이 아님 -> FP 방지)"""
    return is_exploitable_reflection(
        response.text, payload, content_type=response.headers.get("Content-Type")
    )


def run(session, page, payloads: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    parsed = urlparse(page.url)
    query_params = dict(parse_qsl(parsed.query))

    # URL 쿼리 파라미터 검사 (반사형 XSS)
    for param_name in query_params:
        for payload in payloads:
            test_url = _inject_query_param(page.url, param_name, payload)
            try:
                resp = session.get(test_url, timeout=5)
            except Exception:
                continue

            if _is_reflected_unescaped(resp, payload):
                findings.append(make_finding(
                    check_name=CHECK_NAME,
                    url=test_url,
                    parameter=param_name,
                    payload=payload,
                    severity=Severity.MEDIUM,
                    evidence="입력한 payload가 이스케이프 없이, 실행 가능한 HTML 문맥(태그/이벤트 핸들러/URI 속성)에 그대로 반사됨",
                    description="입력값이 HTML에 그대로 출력되어 반사형 XSS로 이어질 가능성이 있습니다.",
                ))
                break

    return findings
