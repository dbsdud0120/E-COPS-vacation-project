"""
checks/idor.py
----------------
IDOR(Insecure Direct Object Reference) / 권한 검증 누락 탐지.

동작 방식:
  1. payloads/idor.txt에서 테스트 계정 2개(username:password)를 읽어 각각 로그인
  2. 크롤링된 페이지 URL 중 숫자 ID가 포함된 경로(예: /api/posts/3)를 대상으로 함
  3. 계정 A/B 세션으로 각각 접근했을 때 응답을 비교
     - 계정 정보가 없으면: "인증 없이도 접근되는지"만 확인 (권한 검증 자체 누락 탐지)
     - 계정 2개가 있으면: 서로 다른 두 계정이 동일 리소스에 똑같이 접근되는지 확인

⚠️ 현재(2주차 시작 시점) Backend의 posts 테이블에는 소유자(user_id) 개념이 없어서,
   "내 것이 아닌 남의 데이터가 보인다"까지는 판별하지 못하고
   "권한 검증이 아예 없다"만 잡습니다. 그래도 이 자체가 실제 보안 이슈이므로
   findings로 기록합니다.

⚙️ Backend가 리소스에 소유자(user_id) 컬럼과 권한 체크를 추가하면:
   - OWNER_FIELD_CANDIDATES에 실제 필드명을 넣고, 아래 TODO 표시된 부분에서
     응답 JSON을 파싱해 "A의 소유물을 B가 볼 수 있는가"까지 비교하도록 확장하세요.

⚙️ payloads/idor.txt 형식 (한 줄에 하나, 최소 2줄 있어야 계정 비교가 활성화됨):
   testuser1:testpass1
   testuser2:testpass2
"""
from __future__ import annotations
import re
from urllib.parse import urlparse

from checks.base import Finding, Severity, make_finding
from auth import login

CHECK_NAME = "idor"

# 응답 JSON에서 소유자를 나타낼 가능성이 있는 필드 이름
# TODO(Backend가 소유자 컬럼 추가 후): 실제 필드명으로 교체하면 소유권 비교 로직을 추가할 수 있음
OWNER_FIELD_CANDIDATES = ["user_id", "owner_id", "writer_id", "username"]

# URL 경로에서 숫자 ID를 찾는 패턴 (예: /api/posts/3, /posts/12/edit)
ID_PATTERN = re.compile(r"/(\d+)(?:/|$|\?)")


def _parse_accounts(payloads: list[str]) -> list[tuple[str, str]]:
    accounts = []
    for line in payloads:
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        username, _, password = line.partition(":")
        accounts.append((username.strip(), password.strip()))
    return accounts


def run(session, page, payloads: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    if not ID_PATTERN.search(page.url):
        return findings  # URL에 숫자 ID가 없는 페이지는 검사 대상 아님

    accounts = _parse_accounts(payloads)

    # 계정이 2개 미만이면: 인증 없이도 접근 가능한지만 확인
    if len(accounts) < 2:
        try:
            resp = session.get(page.url, timeout=5)
        except Exception:
            return findings

        if resp.status_code == 200:
            findings.append(make_finding(
                check_name=CHECK_NAME,
                url=page.url,
                parameter="id",
                payload=None,
                severity=Severity.MEDIUM,
                evidence="인증(로그인) 없이도 ID 기반 리소스에 200 응답으로 접근 가능",
                description=(
                    "객체 접근 시 권한 검증이 없어, 누구나 URL의 ID만 바꿔가며 데이터를 조회할 수 있습니다. "
                    "(payloads/idor.txt에 테스트 계정 2개를 추가하면 계정 간 소유권 비교까지 확인합니다)"
                ),
            ))
        return findings

    # 계정이 2개 이상이면: 서로 다른 두 계정으로 로그인해서 동일 리소스 접근 비교
    (user_a, pass_a), (user_b, pass_b) = accounts[0], accounts[1]

    parsed = urlparse(page.url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    session_a = login(base_url, user_a, pass_a)
    session_b = login(base_url, user_b, pass_b)

    if not session_a or not session_b:
        # 로그인 실패: 계정 정보(payloads/idor.txt) 또는 로그인 스펙(auth.py) 확인 필요
        return findings

    try:
        resp_a = session_a.get(page.url, timeout=5)
        resp_b = session_b.get(page.url, timeout=5)
    except Exception:
        return findings

    # TODO(소유자 필드 추가 후): 여기서 resp_a.json()/resp_b.json()의
    # OWNER_FIELD_CANDIDATES 값을 비교해서, B가 A 소유 리소스를 보고 있는지까지 판별

    if resp_a.status_code == 200 and resp_b.status_code == 200:
        findings.append(make_finding(
            check_name=CHECK_NAME,
            url=page.url,
            parameter="id",
            payload=None,
            severity=Severity.HIGH,
            evidence=f"'{user_a}', '{user_b}' 두 계정 모두 동일 리소스에 200으로 접근 가능 (소유권 검증 없음으로 추정)",
            description="객체 ID에 대한 소유권/권한 검증이 없어, 다른 사용자의 데이터에 접근할 수 있습니다.",
        ))

    return findings
