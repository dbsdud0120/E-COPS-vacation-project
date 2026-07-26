"""
checks/sql_injection.py
------------------------
가장 기본적인 "에러 기반(Error-based) SQL Injection" 탐지 틀.

동작 방식(MVP):
  1. 페이지의 쿼리 파라미터 / form input에 payload를 하나씩 넣어 요청
  2. 응답 본문에 DB 에러 메시지로 흔히 나타나는 문자열이 있는지 확인
  3. 있으면 Finding 생성

주의:
  - 아직 취약 서버가 없어 실제 매칭 여부를 검증하지 못했다.
  - 다음 주차에 취약 서버가 준비되면:
      a) SIGNATURES 목록을 실제 에러 메시지로 보강
      b) 응답시간 기반(Blind/Time-based) 탐지 추가
      c) 정상 응답과의 diff 비교(Boolean-based) 추가
"""

from __future__ import annotations
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from checks.base import Finding, Severity, make_finding

CHECK_NAME = "sql_injection"

# TODO(다음 주차): 실제 DB(MySQL/PostgreSQL/MSSQL/SQLite 등)별 에러 시그니처로 보강
SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "sqlstate",
    "sqlite3.operationalerror",
    "pg_query()",
    "odbc sql server driver",
]


def _inject_query_param(url: str, param: str, payload: str) -> str:
    """URL의 특정 쿼리 파라미터 값을 payload로 치환"""
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    params[param] = payload
    new_query = urlencode(params)
    return urlunparse(parsed._replace(query=new_query))


def _response_has_sql_error(text: str) -> str | None:
    """응답 본문에서 SQL 에러 시그니처를 찾으면 매칭된 문자열 반환"""
    lowered = text.lower()
    for sig in SIGNATURES:
        if sig in lowered:
            return sig
    return None


def run(session, page, payloads: list[str]) -> list[Finding]:
    """
    session: requests.Session (scanner.py에서 전달)
    page:    crawler.PageInfo
    payloads: payloads/sql_injection.txt 에서 로드된 payload 목록
    """
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
                continue  # TODO: 로깅 강화

            matched = _response_has_sql_error(resp.text)
            if matched:
                findings.append(make_finding(
                    check_name=CHECK_NAME,
                    url=test_url,
                    parameter=param_name,
                    payload=payload,
                    severity=Severity.HIGH,
                    evidence=f"응답에서 SQL 에러 시그니처 발견: '{matched}'",
                    description="입력값이 SQL 쿼리에 그대로 삽입되어 DB 에러가 노출될 가능성이 있습니다.",
                ))
                break  # 파라미터당 1개만 기록 (payload 여러 개 반복 방지)

    # 2) form input 검사 (POST 폼)
    # 필드 하나씩 payload를 넣고 나머지 필수 필드는 더미 값으로 채워서 실제로 전송한다.
    # (stored_xss.py와 동일한 패턴: 한 필드당 하나라도 에러 시그니처가 잡히면
    #  다음 payload는 건너뛰고 다음 필드로 넘어간다.)
    for form in page.forms:
        if form.method != "POST":
            continue
        if not form.inputs:
            continue

        for target_field in form.inputs:
            for payload in payloads:
                data = {name: "test" for name in form.inputs}
                data[target_field] = payload

                try:
                    resp = session.post(form.action, data=data, timeout=5)
                except Exception:
                    continue

                matched = _response_has_sql_error(resp.text)
                if matched:
                    findings.append(make_finding(
                        check_name=CHECK_NAME,
                        url=form.action,
                        parameter=target_field,
                        payload=payload,
                        severity=Severity.HIGH,
                        evidence=f"POST 요청 응답에서 SQL 에러 시그니처 발견: '{matched}'",
                        description="입력값이 SQL 쿼리에 그대로 삽입되어 DB 에러가 노출될 가능성이 있습니다.",
                    ))
                    break  # 이 필드는 이미 취약점 확인, 다음 payload는 생략

    return findings
