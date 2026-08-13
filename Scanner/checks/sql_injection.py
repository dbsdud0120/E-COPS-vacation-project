"""
checks/sql_injection.py
------------------------
SQL Injection 탐지 틀. 두 가지 방식을 함께 사용한다.

동작 방식:
  1. 에러 기반(Error-based): 페이지의 쿼리 파라미터 / form input에 payload를 하나씩
     넣어 요청하고, 응답 본문에 DB 에러 메시지로 흔히 나타나는 문자열이 있는지 확인.
  2. 불리언 기반(Boolean-based): /vuln/login처럼 에러 메시지를 노출하지 않고
     "성공/실패" 문구(또는 success:true/false 같은 JSON 필드)만 다르게 응답하는
     케이스를 위한 탐지. 정상적으로는 실패해야 할 입력(baseline)과, SQL 조건이
     참이 되도록 조작한 payload를 각각 보내 응답의 성공/실패 문구가 뒤바뀌는지 비교한다.
     baseline이 "실패" 문구였는데 payload를 넣었을 때 "성공" 문구로 바뀌면,
     입력값이 SQL 조건절에 그대로 삽입되어 인증 로직이 우회된 것으로 판단한다.
     (에러 시그니처가 이미 잡힌 경우는 1)에서 기록하고 2)는 건너뛴다 — 중복 방지)

주의:
  - 응답시간 기반(Blind/Time-based) 탐지는 아직 없음. 필요 시 추가 개선 가능:
      a) 실제 DB(MySQL/PostgreSQL/MSSQL/SQLite 등)별 에러 시그니처로 SIGNATURES 보강
      b) 응답시간 기반(Blind/Time-based) 탐지 추가
"""

from __future__ import annotations
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from checks.base import Finding, Severity, make_finding

CHECK_NAME = "sql_injection"

# DB(MySQL/PostgreSQL/MSSQL/SQLite 등)별 에러 시그니처
SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "sqlstate",
    "sqlite3.operationalerror",
    "pg_query()",
    "odbc sql server driver",
]

# 응답 본문에 에러는 없지만, "성공/실패" 문구(또는 JSON success 필드)만으로
# 결과를 알려주는 엔드포인트(예: /vuln/login)를 위한 판별 키워드.
# ⚠️ 대상 서비스마다 문구가 다를 수 있어, 새 서비스에 적용할 땐 이 목록을 보강해야 함.
SUCCESS_INDICATORS = ["로그인 성공", '"success": true', '"success":true', '"success": true']
FAILURE_INDICATORS = [
    "로그인 실패",
    "아이디 또는 비밀번호가 올바르지 않습니다",
    '"success": false',
    '"success":false',
    '"success": false',
]

# baseline 요청에 사용할, 어떤 계정과도 일치하지 않을 더미 값
BASELINE_PROBE_VALUE = "zzz_scanner_boolean_probe_zzz"


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


def _classify_boolean_response(text: str) -> str | None:
    """
    응답 본문이 "성공" 류 문구인지 "실패" 류 문구인지 분류.
    (에러 시그니처는 없지만 성공/실패 문구만 다른 케이스 판별용)
    둘 다 없으면 None (이 요청/페이지는 boolean 비교 대상이 아님)
    """
    lowered = text.lower()
    if any(ind.lower() in lowered for ind in SUCCESS_INDICATORS):
        return "success"
    if any(ind.lower() in lowered for ind in FAILURE_INDICATORS):
        return "failure"
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
        # boolean 비교용 baseline: 어떤 계정/데이터와도 일치하지 않을 더미 값으로 먼저 요청
        baseline_url = _inject_query_param(page.url, param_name, BASELINE_PROBE_VALUE)
        try:
            baseline_resp = session.get(baseline_url, timeout=5)
            baseline_state = _classify_boolean_response(baseline_resp.text)
        except Exception:
            baseline_state = None

        for payload in payloads:
            test_url = _inject_query_param(page.url, param_name, payload)
            try:
                resp = session.get(test_url, timeout=5)
            except Exception:
                continue  # 요청 실패는 건너뜀

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

            # 에러 시그니처는 없지만, baseline은 "실패"였는데 payload로는 "성공"으로
            # 바뀌는 경우 (예: /vuln/login처럼 성공/실패 문구만 다른 케이스)
            if baseline_state == "failure" and _classify_boolean_response(resp.text) == "success":
                findings.append(make_finding(
                    check_name=CHECK_NAME,
                    url=test_url,
                    parameter=param_name,
                    payload=payload,
                    severity=Severity.HIGH,
                    evidence=(
                        f"더미 값으로는 실패 응답이었으나, payload '{payload}' 입력 시 "
                        f"성공 응답으로 바뀜 (에러 메시지 노출은 없음)"
                    ),
                    description=(
                        "에러 메시지를 노출하지 않아도, 입력값에 따라 응답의 성공/실패 문구가 "
                        "달라져 SQL 조건절이 조작 가능한 Boolean-based SQL Injection으로 의심됩니다."
                    ),
                ))
                break  # 파라미터당 1개만 기록

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
            # boolean 비교용 baseline: 대상 필드만 더미 값, 나머지는 기존과 동일하게 "test"로 채움
            baseline_data = {name: "test" for name in form.inputs}
            baseline_data[target_field] = BASELINE_PROBE_VALUE
            try:
                baseline_resp = session.post(form.action, data=baseline_data, timeout=5)
                baseline_state = _classify_boolean_response(baseline_resp.text)
            except Exception:
                baseline_state = None

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

                # 에러 시그니처는 없지만, baseline은 "실패"였는데 payload로는 "성공"으로
                # 바뀌는 경우 (예: /vuln/login처럼 성공/실패 문구만 다른 케이스)
                if baseline_state == "failure" and _classify_boolean_response(resp.text) == "success":
                    findings.append(make_finding(
                        check_name=CHECK_NAME,
                        url=form.action,
                        parameter=target_field,
                        payload=payload,
                        severity=Severity.HIGH,
                        evidence=(
                            f"더미 값으로는 실패 응답이었으나, payload '{payload}' 입력 시 "
                            f"성공 응답으로 바뀜 (에러 메시지 노출은 없음)"
                        ),
                        description=(
                            "에러 메시지를 노출하지 않아도, 입력값에 따라 응답의 성공/실패 문구가 "
                            "달라져 SQL 조건절이 조작 가능한 Boolean-based SQL Injection으로 의심됩니다."
                        ),
                    ))
                    break  # 이 필드는 이미 취약점 확인, 다음 payload는 생략

    return findings
