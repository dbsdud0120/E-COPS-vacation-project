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
       + 응답이 JSON이고 OWNER_FIELD_CANDIDATES에 해당하는 소유자 필드를 담고 있으면,
         그 값이 계정 A/B 중 누구 것인지까지 비교해서 "실제 타 계정 소유 데이터 접근"을
         HIGH로 구분해서 기록한다 (아래 6주차 갱신 내용 참고).

✅ (6주차 갱신) Backend posts 테이블에 user_id 컬럼이 추가되었고, /api/posts,
   /api/posts/<id> 응답 JSON에 소유자 정보로 "writer"(작성자 username)가 포함됨을
   확인했다. 이에 맞춰 OWNER_FIELD_CANDIDATES에 "writer"를 추가하고, 두 계정 응답을
   비교할 때 응답 JSON의 소유자 필드 값이 로그인한 두 계정 중 한쪽(A 또는 B)과
   일치하는데 다른 쪽 계정으로도 200이 나오면 "타 계정 소유 데이터 접근(BOLA)"으로
   판정하도록 구현을 확장했다.
   - 소유자 필드를 못 찾은 경우(응답이 JSON이 아니거나 후보 필드가 전혀 없는 경우)에는
     예전처럼 "권한 검증 없음으로 추정"만 기록한다 (오탐 방지를 위해 소유권 단정을 하지 않음).
   - /posts/edit, /posts/delete 처럼 인증·소유자 검증이 있는 정상 엔드포인트에서는
     본 검사가 200을 받지 못하므로(비로그인/타 계정은 차단) findings가 발생하지 않고,
     /vuln/posts/edit, /vuln/posts/delete 처럼 의도적으로 취약한 엔드포인트에서만
     탐지되는 것을 확인했다.

⚙️ payloads/idor.txt 형식 (한 줄에 하나, 최소 2줄 있어야 계정 비교가 활성화됨):
   testuser1:testpass1
   testuser2:testpass2

⚠️ 안전장치: URL 경로에 delete/remove/drop 등 "삭제"로 보이는 단어가 포함되면
   실제 요청을 보내지 않습니다. (예: /posts/delete/3, /vuln/posts/delete/3처럼
   GET 요청 하나로 실제 삭제가 실행되는 엔드포인트가 있어, 스캔 중 데이터가
   삭제되는 걸 막기 위함) 이 경우 "발견은 했으나 실행하지 않음"으로만 기록되며,
   실제로 인증/권한 없이 삭제가 가능한지는 수동으로 확인해야 합니다.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse

from checks.base import Finding, Severity, make_finding
from auth import login

CHECK_NAME = "idor"

# 응답 JSON에서 소유자를 나타낼 가능성이 있는 필드 이름
# (6주차) Backend /api/posts, /api/posts/<id> 응답에 실제로 포함되는 "writer"(작성자 username)를 추가함
OWNER_FIELD_CANDIDATES = ["user_id", "owner_id", "writer_id", "writer", "username"]

# URL 경로에서 숫자 ID를 찾는 패턴 (예: /api/posts/3, /posts/12/edit)
ID_PATTERN = re.compile(r"/(\d+)(?:/|$|\?)")

# 이 단어가 경로에 포함되면 실제 요청을 보내지 않음 (GET만으로 상태를 바꾸는 엔드포인트 방지)
DESTRUCTIVE_PATH_HINTS = ("delete", "remove", "drop")


def _looks_destructive(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(hint in path for hint in DESTRUCTIVE_PATH_HINTS)


def _extract_owner(resp) -> str | None:
    """응답 JSON에서 OWNER_FIELD_CANDIDATES에 해당하는 소유자 값을 찾아 문자열로 반환.
    JSON이 아니거나 후보 필드가 없으면 None (소유권 비교 불가로 처리)."""
    try:
        data = resp.json()
    except ValueError:
        return None

    if not isinstance(data, dict):
        return None

    for field in OWNER_FIELD_CANDIDATES:
        value = data.get(field)
        if value not in (None, ""):
            return str(value)

    return None


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

    if _looks_destructive(page.url):
        # 실제 삭제를 유발하지 않기 위해 요청을 보내지 않고 "발견"만 기록
        findings.append(make_finding(
            check_name=CHECK_NAME,
            url=page.url,
            parameter="id",
            payload=None,
            severity=Severity.HIGH,
            evidence="URL 경로에 삭제(delete) 등 상태 변경 작업으로 보이는 단어가 포함되어, 실제 요청은 보내지 않았습니다.",
            description=(
                "이 엔드포인트가 인증/권한 검증 없이 GET 요청만으로 데이터를 삭제/변경할 수 있는지 "
                "수동으로 확인이 필요합니다. 자동 스캔에서는 실제 데이터 손실을 막기 위해 요청을 생략했습니다."
            ),
        ))
        return findings

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

    if resp_a.status_code == 200 and resp_b.status_code == 200:
        # 응답 JSON에서 소유자 필드(예: writer)를 뽑아, 두 계정 중 누구 소유인지 확인
        owner = _extract_owner(resp_a) or _extract_owner(resp_b)

        if owner in (user_a, user_b):
            victim, attacker = (user_a, user_b) if owner == user_a else (user_b, user_a)
            findings.append(make_finding(
                check_name=CHECK_NAME,
                url=page.url,
                parameter="id",
                payload=None,
                severity=Severity.HIGH,
                evidence=(
                    f"리소스 소유자는 '{victim}'이지만, 다른 계정 '{attacker}'로도 "
                    f"동일 리소스에 200으로 접근하여 소유자가 아닌 데이터를 열람함"
                ),
                description=(
                    "객체 소유권 검증(BOLA/Broken Object Level Authorization)이 없어, "
                    "로그인한 다른 사용자가 자신의 것이 아닌 타 계정 소유 데이터를 실제로 조회할 수 있습니다."
                ),
            ))
        else:
            # 응답이 JSON이 아니거나 소유자 필드를 못 찾은 경우: 소유권 비교는 불가하므로
            # (기존과 동일하게) "권한 검증 없음으로 추정"만 기록해 오탐을 피한다.
            findings.append(make_finding(
                check_name=CHECK_NAME,
                url=page.url,
                parameter="id",
                payload=None,
                severity=Severity.HIGH,
                evidence=(
                    f"'{user_a}', '{user_b}' 두 계정 모두 동일 리소스에 200으로 접근 가능 "
                    "(응답에서 소유자 필드를 확인하지 못해 소유권 비교는 불가, 권한 검증 없음으로 추정)"
                ),
                description="객체 ID에 대한 소유권/권한 검증이 없어, 다른 사용자의 데이터에 접근할 수 있습니다.",
            ))

    return findings
