"""
checks/idor.py
----------------
IDOR(Insecure Direct Object Reference) / 권한 검증 누락 탐지.

⚠️ 범위와 한계
   이 check은 범용 IDOR 오라클이 아니라, "권한 검증에 실패해도 403/401이 아니라 200
   상태 코드 + 짧은 안내 문구를 그대로 돌려주는" 이 프로젝트 Backend 패턴에 맞춰
   튜닝된 블랙박스 휴리스틱이다. 상태 코드만으로는 성공/거부를 구분할 수 없어서
   응답 본문을 비교하는 방식으로 판단하는데, 아래 가정에 의존한다:
     - 정상적으로 접근된 응답(진짜 데이터)은 거부 응답보다 내용이 뚜렷이 다르다.
     - 같은 리소스에 대해 서로 다른 두 계정이 "진짜 데이터"를 받았다면 그 내용은
       사실상 동일하다(같은 객체이므로).
   대상 앱이 이 가정과 다르게 동작하면(예: 성공 응답이 계정마다 크게 다르게 개인화되어
   있거나, 거부 응답이 매우 크고 구조화되어 있다면) 오탐/미탐이 생길 수 있다. 확정적
   판단이 필요하면 evidence를 참고해 수동으로 재현/검증할 것.

동작 방식:
  1. payloads/idor.txt에서 테스트 계정 2개(username:password)를 읽어 각각 로그인
  2. 크롤링된 페이지 URL 중 숫자 ID가 포함된 경로(예: /api/posts/3)를 대상으로 함
  3. 계정 A/B 세션으로 각각 접근했을 때 응답을 비교
     - 계정 정보가 없으면: 별도의 비인증(anonymous) 세션으로 "인증 없이도 접근되는지"만
       확인 (권한 검증 자체 누락 탐지). scanner.py가 다른 check(stored_xss 등)를 위해
       미리 로그인해둔 session을 넘겨주더라도, 이 분기는 그 session을 쓰지 않고 항상
       새 익명 세션으로 직접 요청한다.
     - 계정 2개가 있으면: 서로 다른 두 계정이 동일 리소스에 똑같이 접근되는지 확인
       + 응답이 JSON이고 OWNER_FIELD_CANDIDATES에 해당하는 소유자 필드를 담고 있으면
         (중첩된 dict/list 안까지 얕은 깊이로 탐색), 그 값이 계정 A/B 중 누구 것인지까지
         비교해서 "실제 타 계정 소유 데이터 접근"을 HIGH로 구분해서 기록한다. 이때도
         "상대 계정"의 응답이 진짜 데이터인지 비로그인 기준선과 비교해 확인한다
         (_confirms_real_access).
       + 소유자 필드를 못 찾은 경우:
         - 비로그인 요청조차 실데이터를 받는다면(=인증 자체가 없는 완전 개방형 접근),
           계정 비교보다 더 심각한 신호이므로 HIGH로 기록한다.
         - 그 외에는 A/B 응답이 각각 실제 접근 성공으로 볼 근거가 있는지, 그리고
           서로 실제로 같은 내용인지(quick_ratio 기반 내용 유사도 + 길이)를 함께 봐서
           MEDIUM으로 낮춰 기록한다.

⚙️ payloads/idor.txt 형식 (한 줄에 하나, 최소 2줄 있어야 계정 비교가 활성화됨):
   testuser1:testpass1
   testuser2:testpass2

⚠️ 안전장치: URL 경로에 delete/remove/drop 등 "삭제"로 보이는 단어가 포함되면
   실제 요청을 보내지 않습니다. (예: /posts/delete/3, /vuln/posts/delete/3처럼
   GET 요청 하나로 실제 삭제가 실행되는 엔드포인트가 있어, 스캔 중 데이터가
   삭제되는 걸 막기 위함)

   이 판단(safety.looks_destructive)의 1차 방어선은 이제 crawler.py에 있다 —
   크롤러/swagger 시드 단계가 이런 URL을 아예 실제로 요청하지 않고 status_code=-1로
   처리해서, scanner.py의 메인 루프가 어떤 check도 그 페이지에 접근하지 못하게
   걸러준다 (예전엔 idor.py의 이 가드가 유일한 방어선이었는데, 크롤러/swagger 시드
   단계가 이미 그보다 먼저 실제 GET 요청을 보내버려서 늦은 시점이었다 — 실제로 이
   때문에 /vuln/posts/delete/<id> 방문만으로 게시글이 삭제되는 걸 재현 확인함).
   여기 남아있는 검사는 idor.run()이 크롤러를 거치지 않은 다른 경로로 호출되는 경우를
   대비한 2차 방어선이며, 정상 흐름에서는 도달하지 않는다. 도달하더라도 실제로 검증한
   게 아니므로 INFO로만 기록되며, 인증/권한 없이 삭제가 가능한지는 수동으로 확인해야
   합니다.
"""
from __future__ import annotations
import difflib
import re
from urllib.parse import urlparse

import requests

from checks.base import Finding, Severity, make_finding
from auth import login
from safety import looks_destructive

CHECK_NAME = "idor"

# 응답 JSON에서 소유자를 나타낼 가능성이 있는 필드 이름
# Backend /api/posts, /api/posts/<id> 응답에 포함되는 "writer"(작성자 username) 포함
OWNER_FIELD_CANDIDATES = ["user_id", "owner_id", "writer_id", "writer", "username"]

# URL 경로에서 숫자 ID를 찾는 패턴 (예: /api/posts/3, /posts/12/edit)
ID_PATTERN = re.compile(r"/(\d+)(?:/|$|\?)")

# 응답 유사도 판단 기준: 길이 차이 허용 오차(%)와 내용 유사도(quick_ratio) 최소값
_LENGTH_TOLERANCE_RATIO = 0.15
_MIN_LENGTH_TOLERANCE = 50
_SIMILARITY_THRESHOLD = 0.85

# _looks_substantive()에서 "충분히 긴 본문"으로 볼 최소 길이
_SUBSTANTIVE_MIN_LENGTH = 300

# JSON에서 소유자 필드를 재귀 탐색할 때의 상한 (비정상적으로 깊거나 큰 응답 방어)
_OWNER_SEARCH_MAX_DEPTH = 4
_OWNER_SEARCH_MAX_NODES = 200


def _extract_owner(resp) -> str | None:
    """응답 JSON에서 OWNER_FIELD_CANDIDATES에 해당하는 소유자 값을 찾아 문자열로 반환.

    최상위 dict만 보면 {"post": {...}}, {"data": {...}}, [{"writer": ...}, ...] 같은
    흔한 응답 래핑 구조를 놓치므로, dict/list를 얕은 깊이(_OWNER_SEARCH_MAX_DEPTH)까지
    BFS로 재귀 탐색한다. 너무 크거나 깊은 JSON에서 오래 걸리지 않도록 방문 노드 수도
    제한한다.
    JSON이 아니거나 후보 필드를 못 찾으면 None (소유권 비교 불가로 처리)."""
    try:
        data = resp.json()
    except ValueError:
        return None

    queue = [(data, 0)]
    visited = 0

    while queue:
        node, depth = queue.pop(0)
        visited += 1
        if visited > _OWNER_SEARCH_MAX_NODES:
            break

        if isinstance(node, dict):
            for field in OWNER_FIELD_CANDIDATES:
                value = node.get(field)
                if value not in (None, ""):
                    return str(value)
            if depth < _OWNER_SEARCH_MAX_DEPTH:
                for value in node.values():
                    if isinstance(value, (dict, list)):
                        queue.append((value, depth + 1))
        elif isinstance(node, list):
            if depth < _OWNER_SEARCH_MAX_DEPTH:
                for item in node:
                    if isinstance(item, (dict, list)):
                        queue.append((item, depth + 1))

    return None


def _anon_baseline_resp(url: str):
    """비로그인 상태로 같은 URL을 한 번 요청해 '접근이 거부됐을 때 응답이 어떻게 생겼는지'를
    기준선으로 확보한다.

    Flask 등 일부 앱은 권한 검증에 실패해도 403/401이 아니라 200 상태 코드에 짧은 안내
    문구("로그인이 필요합니다", "작성자만 수정할 수 있습니다" 등)를 그대로 돌려준다. 이 경우
    status_code == 200 만으로는 "실제 데이터에 접근했다"고 판단할 수 없다. 실패 시(네트워크
    오류 등)에는 None을 반환하고, 호출부는 기준선 비교 없이 기존 로직으로 fallback 한다.

    ⚠️ 주의: 이 기준선이 항상 "거부 응답"이라는 보장은 없다. 대상 엔드포인트에 애초에
    인증 검증이 전혀 없다면(가장 심각한 케이스), 비로그인 요청도 실제 데이터를 그대로
    받는다. 그래서 호출부는 이 응답 자체가 substantive(=실데이터로 보이는지)도 함께
    확인해야 한다 (_looks_substantive 참고) — "로그인한 계정 응답이 기준선과 같다"는
    사실만으로 곧장 "거부됐다"고 판단하면 안 된다."""
    try:
        return requests.Session().get(url, timeout=5)
    except Exception:
        return None


def _similarity(text_a: str, text_b: str) -> float:
    """0~1 사이의 본문 유사도. quick_ratio()는 완전한 비교(O(n^2))보다 훨씬 빠르면서도
    "거의 같은 문서인지"를 판단하기엔 충분한 근사치를 준다."""
    if not text_a and not text_b:
        return 1.0
    return difflib.SequenceMatcher(None, text_a, text_b).quick_ratio()


def _resembles(text_a: str, text_b: str | None) -> bool:
    """두 응답 본문이 사실상 같은 문서(같은 문구/데이터)인지 판단.

    길이만 비교하면 우연히 길이가 비슷한 서로 다른 내용을 "같다"고 오판할 수 있어서,
    (1) 길이가 서로 근접하고 (2) 실제 본문 유사도(quick_ratio)도 임계값 이상일 때만
    "같은 응답"으로 판단한다."""
    if text_b is None:
        return False
    base_len = len(text_b)
    tolerance = max(_MIN_LENGTH_TOLERANCE, int(base_len * _LENGTH_TOLERANCE_RATIO))
    if abs(len(text_a) - base_len) > tolerance:
        return False
    return _similarity(text_a, text_b) >= _SIMILARITY_THRESHOLD


def _looks_substantive(resp) -> bool:
    """응답이 '실제 데이터'로 보이는지에 대한 대략적인 신호.

    (1) 비어있지 않은 구조화된 JSON(dict/list)이거나
    (2) HTML이라도 폼/표 등 구조적 태그를 포함하거나
    (3) 충분히 긴 본문(단순 안내 문구 한두 줄보다 김)
    이면 True. 셋 다 아니면 "로그인이 필요합니다" 류의 짧은 안내 문구일 가능성이 높다고
    보고 False. (비인증 접근 확인처럼 비교할 다른 응답이 없는 경우에 사용)"""
    try:
        data = resp.json()
    except ValueError:
        data = None

    if isinstance(data, (dict, list)) and data:
        return True

    text = resp.text.strip()
    if any(tag in text.lower() for tag in ("<form", "<table", "<input", "<article")):
        return True

    return len(text) > _SUBSTANTIVE_MIN_LENGTH


def _confirms_real_access(resp, baseline_resp) -> bool:
    """resp가 실제로 보호된 데이터에 '접근 성공'했다고 볼 근거가 있는지 판단.

    (1) resp 자체가 substantive(=실데이터로 보이는)하지 않으면 애초에 접근 성공으로
        볼 수 없다.
    (2) resp가 substantive해도, 비로그인 기준선(baseline_resp)과 사실상 같은 응답이면서
        그 기준선 자체는 substantive하지 않다면(=비로그인은 짧은 거부 문구를 받는 게
        정상인데 resp만 그것과 같다는 건 모순이라 실제로는 거의 발생하지 않지만, 방어적으로
        체크) 신뢰하지 않는다.
    (3) 반대로 baseline_resp 자체도 substantive하다면(=비로그인 요청조차 실데이터를 받는
        완전 개방형 접근), resp가 baseline과 같아도 여전히 '접근 성공'으로 판단한다.
        이건 "baseline과 같으니 거부됐을 것"이라고 억제하면 안 되는 경우 — 오히려 더
        심각한(인증 자체가 없는) 신호이기 때문이다."""
    if not _looks_substantive(resp):
        return False
    if baseline_resp is not None and _resembles(resp.text, baseline_resp.text) and not _looks_substantive(baseline_resp):
        return False
    return True


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

    if looks_destructive(page.url):
        # 실제 삭제를 유발하지 않기 위해 요청을 보내지 않고 "발견"만 기록.
        # 실제 요청을 안 보내 취약 여부를 확인한 게 아니므로(단순 URL 경로 이름 매칭일
        # 뿐), HIGH로 확정하지 않고 "수동 확인 필요" 수준인 INFO로 기록한다.
        findings.append(make_finding(
            check_name=CHECK_NAME,
            url=page.url,
            parameter="id",
            payload=None,
            severity=Severity.INFO,
            evidence="URL 경로에 삭제(delete) 등 상태 변경 작업으로 보이는 단어가 포함되어, 실제 요청은 보내지 않았습니다.",
            description=(
                "이 엔드포인트가 인증/권한 검증 없이 GET 요청만으로 데이터를 삭제/변경할 수 있는지 "
                "수동으로 확인이 필요합니다. 자동 스캔에서는 실제 데이터 손실을 막기 위해 요청을 생략했습니다."
            ),
        ))
        return findings

    accounts = _parse_accounts(payloads)

    # 계정이 2개 미만이면: 인증 없이도 접근 가능한지만 확인.
    # 주의: scanner.py의 run_scan()이 다른 check(stored_xss 등)를 위해 미리 로그인해둔
    # session을 모든 check에 그대로 넘겨준다. 여기서 그 session을 그대로 쓰면 "비인증
    # 검사"가 실제로는 인증된 상태로 이뤄지는 버그가 생기므로, 항상 새 익명 세션으로
    # 직접 요청한다 (전달받은 session 파라미터는 이 분기에서 의도적으로 쓰지 않음).
    if len(accounts) < 2:
        try:
            anon_resp = requests.Session().get(page.url, timeout=5)
        except Exception:
            return findings

        if anon_resp.status_code == 200 and _looks_substantive(anon_resp):
            findings.append(make_finding(
                check_name=CHECK_NAME,
                url=page.url,
                parameter="id",
                payload=None,
                severity=Severity.MEDIUM,
                evidence="인증(로그인) 없이도 ID 기반 리소스에 200 응답 + 실제 데이터로 보이는 내용으로 접근 가능",
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
            attacker_resp = resp_b if owner == user_a else resp_a

            # owner 필드가 resp_a/resp_b 어느 한쪽에서 발견됐다고 해서 상대(attacker) 쪽
            # 응답이 반드시 "진짜 데이터"라는 보장은 없다. 비로그인 기준선과 비교해서
            # 실제로 접근 성공으로 볼 근거가 있는지 확인한다 (_confirms_real_access 참고 —
            # 비로그인조차 뚫려있는 경우는 오히려 더 심각하므로 억제하지 않는다).
            baseline_resp = _anon_baseline_resp(page.url)
            if not _confirms_real_access(attacker_resp, baseline_resp):
                return findings

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
            # 응답이 JSON이 아니거나 소유자 필드를 못 찾은 경우: 두 계정 모두 200을 받았어도
            # 그게 "진짜 데이터"인지, 아니면 권한 실패도 200 + 안내 문구로 내려주는 것뿐인지
            # 알 수 없다. 비로그인 기준선을 확보해 두 단계로 확인한다.
            baseline_resp = _anon_baseline_resp(page.url)

            # 1) 익명 사용자조차 실데이터를 받는 경우(=인증 검증이 아예 없는 완전 개방형
            #    접근)는 계정 간 비교보다 더 심각한 신호이므로 먼저 확인해서 HIGH로 올린다.
            #    (이전 버전은 "계정 응답이 비로그인 응답과 같으면 거부됐다"고만 판단해서,
            #    비로그인도 뚫려 있는 이 케이스를 거꾸로 놓치는 미탐이 있었음 — 실제
            #    /vuln/posts/edit/<id>로 재현 확인 후 이번에 수정.)
            if (
                baseline_resp is not None
                and _looks_substantive(baseline_resp)
                and (_resembles(resp_a.text, baseline_resp.text) or _resembles(resp_b.text, baseline_resp.text))
            ):
                findings.append(make_finding(
                    check_name=CHECK_NAME,
                    url=page.url,
                    parameter="id",
                    payload=None,
                    severity=Severity.HIGH,
                    evidence=(
                        "비로그인 상태에서도 동일 리소스에 200 응답 + 실데이터로 보이는 내용으로 "
                        f"접근 가능하며, '{user_a}', '{user_b}' 계정도 사실상 같은 내용을 받음"
                    ),
                    description=(
                        "객체에 대한 인증/권한 검증이 전혀 없어, 로그인하지 않은 사용자도 "
                        "URL의 ID만 바꿔가며 데이터를 조회/열람할 수 있습니다."
                    ),
                ))
                return findings

            # 2) 그 외의 경우: A/B 응답 각각이 실제 접근 성공으로 볼 근거가 있는지
            #    (_confirms_real_access — 비로그인 기준선과 같으면서 기준선이 짧은 거부
            #    문구인 경우는 걸러냄) 확인하고, 그 위에서 A/B끼리 실제로 같은 내용인지
            #    비교한다 (이전 버전은 이 A/B 비교가 주석에만 있었고 코드에는 없었음 —
            #    이번에 실제로 구현).
            if (
                _confirms_real_access(resp_a, baseline_resp)
                and _confirms_real_access(resp_b, baseline_resp)
                and _resembles(resp_a.text, resp_b.text)
            ):
                # baseline과는 다르고, A/B 응답끼리는 사실상 같은 내용 -> 서로 다른 두
                # 계정이 같은 실데이터를 봤을 가능성이 높음. 소유자 필드로 확증한 경우
                # (위 HIGH 분기)보다는 신뢰도가 낮으므로 MEDIUM으로 기록한다.
                findings.append(make_finding(
                    check_name=CHECK_NAME,
                    url=page.url,
                    parameter="id",
                    payload=None,
                    severity=Severity.MEDIUM,
                    evidence=(
                        f"'{user_a}', '{user_b}' 두 계정이 동일 리소스에 200으로 접근했고, "
                        "두 응답 내용이 비로그인 상태와는 다르면서 서로는 사실상 동일함(=같은 "
                        "실데이터로 추정). 다만 응답에서 소유자 필드를 확인하지 못해 확정적 "
                        "소유권 비교는 불가하여 MEDIUM으로 기록함 (수동 확인 권장)."
                    ),
                    description="객체 ID에 대한 소유권/권한 검증이 없을 가능성이 있어, 다른 사용자의 데이터에 접근할 수 있는지 수동 확인이 필요합니다.",
                ))
            # A/B가 baseline과도 다르고 서로도 다르면(각자 다른 내용을 받은 경우 등)
            # 근거가 불충분하므로 오탐 방지를 위해 기록하지 않는다.

    return findings
