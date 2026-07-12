"""
checks/stored_xss.py
----------------------
저장형(Stored) XSS 탐지: POST form에 고유 마커가 포함된 payload를 제출한 뒤,
페이지를 다시 조회해서 마커가 이스케이프 없이 그대로 남아있는지 확인.

⚠️ Backend 구조: 글 작성은 `/posts`에서 하지만, 이스케이프 없이 그대로 출력하는
   페이지는 `/vuln/posts`로 분리되어 있습니다 (`/posts`가 쓰는 posts.html은
   정상적으로 autoescape되어 있어 안전함). 그래서 payload 제출 후 `page.url`
   (=/posts) 하나만 재조회하면 findings가 0건으로 나오고, `/vuln/posts`도
   같이 재조회해야 실제로 탐지됩니다. 아래 REVISIT_URL_OVERRIDES가 이 매핑을
   담당합니다.

⚙️ Backend가 폼/라우팅 구조를 바꾸면 확인할 것:
   - 폼 input 이름/개수가 달라져도 나머지 필수 입력값은 DUMMY_VALUE로 자동
     채우기 때문에 대부분은 그대로 동작합니다.
   - "제출 페이지 -> 확인 페이지" 매핑이 추가/변경되면 REVISIT_URL_OVERRIDES에
     한 줄만 추가/수정하면 됩니다.
"""
from __future__ import annotations
import uuid
from urllib.parse import urljoin, urlparse

from checks.base import Finding, Severity, make_finding

CHECK_NAME = "stored_xss"

DUMMY_VALUE = "test"  # payload를 넣지 않는 나머지 필수 입력값을 채울 더미 값

# form이 제출되는 경로(action의 path) -> 결과가 이스케이프 없이 출력되는 실제 확인 경로
# Backend/app.py 기준: /posts로 글을 쓰면 /vuln/posts에서 이스케이프 없이 보여줌
# TODO(Backend 변경 시): 매핑이 추가/변경되면 여기 한 줄만 수정
REVISIT_URL_OVERRIDES = {
    "/posts": "/vuln/posts",
}


def _build_payload(marker: str) -> str:
    return f"<script>alert('{marker}')</script>"


def _revisit_targets(page_url: str, form_action: str) -> list[str]:
    """payload 제출 후 재조회할 URL 목록 (원래 페이지 + override로 매핑된 확인 페이지)"""
    targets = [page_url]

    action_path = urlparse(form_action).path
    override_path = REVISIT_URL_OVERRIDES.get(action_path)
    if override_path:
        override_url = urljoin(form_action, override_path)
        if override_url not in targets:
            targets.append(override_url)

    return targets


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

            # 제출이 반영됐을 만한 페이지들을 순서대로 재조회
            # (원래 page.url뿐 아니라, REVISIT_URL_OVERRIDES에 매핑된 "실제 확인 페이지"도 포함)
            for revisit_url in _revisit_targets(page.url, form.action):
                try:
                    revisit = session.get(revisit_url, timeout=5)
                except Exception:
                    continue

                if payload in revisit.text:
                    findings.append(make_finding(
                        check_name=CHECK_NAME,
                        url=form.action,
                        parameter=target_field,
                        payload=payload,
                        severity=Severity.HIGH,
                        evidence=f"제출한 스크립트가 '{revisit_url}' 재조회 시 이스케이프 없이 그대로 노출됨 (marker={marker})",
                        description="입력값이 DB에 저장된 뒤 이스케이프 없이 다시 출력되어, 페이지를 열람하는 모든 사용자에게 스크립트가 실행될 수 있습니다.",
                    ))
                    break  # 한 필드당 1건만 기록 (여러 확인 페이지에 중복 기록 방지)
            # payload 자체는 없지만 marker(원문 문자열)만 이스케이프된 채 보인다면
            # "저장은 되지만 이스케이프도 됨" = 취약하지 않은 정상 케이스라 별도 기록하지 않음

    return findings
