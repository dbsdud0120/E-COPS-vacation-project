"""
checks/stored_xss.py
----------------------
저장형(Stored) XSS 탐지: POST form에 고유 마커가 포함된 payload를 제출한 뒤,
같은 페이지를 다시 조회해서 마커가 이스케이프 없이 그대로 남아있는지 확인.

⚠️ 현재(2주차 시작 시점) Backend의 /posts는 Jinja2 기본 autoescape가 걸려 있어서
   payload를 넣어도 이스케이프되어 출력됩니다. 즉 지금은 findings가 0건이 정상이며,
   이는 "검사가 안 됨"이 아니라 "실제로 취약하지 않음"을 뜻합니다.
   Backend가 posts.html 등에 의도적 취약점(|safe 필터 등)을 넣으면
   이 파일은 수정 없이 바로 탐지합니다.

⚙️ Backend가 폼 구조를 바꾸면 확인할 것:
   - 폼 input 이름/개수가 달라져도 나머지 필수 입력값은 DUMMY_VALUE로 자동
     채우기 때문에 대부분은 그대로 동작합니다.
   - "제출 후 다시 조회할 URL"이 폼이 있던 페이지(page.url)와 다르다면
     (예: 제출은 /posts, 결과 확인은 /board/list처럼 분리된 경우) revisit
     대상 URL을 별도로 지정하도록 이 부분을 수정해야 합니다.
"""
from __future__ import annotations
import uuid

from checks.base import Finding, Severity, make_finding

CHECK_NAME = "stored_xss"

DUMMY_VALUE = "test"  # payload를 넣지 않는 나머지 필수 입력값을 채울 더미 값


def _build_payload(marker: str) -> str:
    return f"<script>alert('{marker}')</script>"


def run(session, page, payloads: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    post_forms = [f for f in page.forms if f.method == "POST"]
    if not post_forms:
        return findings

    for form in post_forms:
        if not form.inputs:
            continue

        # 실행마다 고유한 마커 사용 -> 나중에 재조회 결과에서 "내가 넣은 값"인지 명확히 구분
        marker = f"XSS_{uuid.uuid4().hex[:8]}"
        payload = _build_payload(marker)

        # 입력 필드를 하나씩 돌아가며 payload를 넣고, 나머지 필수 필드는 더미 값으로 채움
        for target_field in form.inputs:
            data = {name: DUMMY_VALUE for name in form.inputs}
            data[target_field] = payload

            try:
                session.post(form.action, data=data, timeout=5)
            except Exception:
                continue

            # 제출이 반영된 페이지를 다시 조회 (게시판이면 목록 페이지 = page.url인 경우가 많음)
            try:
                revisit = session.get(page.url, timeout=5)
            except Exception:
                continue

            if payload in revisit.text:
                findings.append(make_finding(
                    check_name=CHECK_NAME,
                    url=form.action,
                    parameter=target_field,
                    payload=payload,
                    severity=Severity.HIGH,
                    evidence=f"제출한 스크립트가 '{page.url}' 재조회 시 이스케이프 없이 그대로 노출됨 (marker={marker})",
                    description="입력값이 DB에 저장된 뒤 이스케이프 없이 다시 출력되어, 페이지를 열람하는 모든 사용자에게 스크립트가 실행될 수 있습니다.",
                ))
            # payload 자체는 없지만 marker(원문 문자열)만 이스케이프된 채 보인다면
            # "저장은 되지만 이스케이프도 됨" = 취약하지 않은 정상 케이스라 별도 기록하지 않음

    return findings
