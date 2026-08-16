"""
safety.py
---------
크롤링/시드 단계 및 mutation을 일으키는 check들이 공유하는 "이 URL을 이렇게 다뤄도
안전한가" 판단 유틸리티. 두 가지를 다룬다:

1. looks_destructive(url): GET 요청 자체가 상태를 바꿔버리는(삭제 등) URL인지 판단.
   크롤러가 이런 URL은 아예 요청을 보내지 않도록 하는 데 쓰인다 (아래 배경 참고).
2. is_unsafe_mutation_target(url): GET은 안전하지만 그 페이지의 POST form을 실제로
   제출하면 문제가 되는 URL인지 판단 (아래 두 경우를 합친 것). SQL Injection/XSS/
   Stored XSS처럼 "form에 실제로 POST"하는 check들이 이런 form을 건드리지 않게 하는
   데 쓰인다. GET 자체는 안전하므로 크롤러 차단 대상은 아니며, IDOR의 GET 기반
   비교에는 계속 사용된다.
     a) is_mutating_edit_form: 실제 데이터(게시글 등)를 수정하는 form
     b) creates_persistent_account: 실제 계정을 생성하는 form (/signup) — 여기 임의
        payload를 제출하면 그 payload가 실제 로그인 정보가 되어, 같은 스캔 안에서
        다른 페이지를 검사할 때 "SQL Injection처럼 보이는" 오탐을 유발할 수 있다
        (실제로 재현 확인, 아래 두 번째 배경 참고).

⚠️ 배경 (looks_destructive가 왜 필요해졌는가):
이전 버전에서는 이 가드가 checks/idor.py 안에만 있었다. 문제는, idor.py의 가드가
실행되는 시점은 이미 "check를 실행하는 단계"인데, 그보다 훨씬 전인 크롤링/swagger 시드
단계(run_scan()이 swagger에 문서화된 GET 가능한 경로를 미리 방문해 크롤링 결과 목록에
추가하는 과정, crawler.py의 Crawler.crawl()/visit_extra())에서 이미 실제 GET 요청을
서버로 보내버린다.

이 프로젝트의 /vuln/posts/delete/<id>처럼 GET 요청 하나만으로 실제 삭제가 일어나는
엔드포인트가 있으면(그리고 swagger.yaml에 GET으로 문서화돼 있으면), "그냥 페이지 목록에
추가하려고 방문"한 것만으로 데이터가 사라진다 — idor.py의 가드는 이미 늦은 시점이라 이걸
못 막는다. (실제로 스캔 테스트 중 이 경로로 게시글이 삭제되는 걸 재현 확인함.)

게다가 security_headers.py/jwt_verification.py 등 다른 check들도 page.url에 자기
request를 직접 보내므로, idor.py 하나만 고쳐서는 다른 check가 같은 페이지를 또 건드릴 때
똑같은 문제가 재발할 수 있다.

그래서 이 판단을 "실제 네트워크 요청을 보내기 전, 가장 이른 지점"인 크롤러 레벨로
옮겼다. crawler.py가 이 모듈을 사용해 파괴적으로 보이는 URL은 아예 요청 자체를 보내지
않고 status_code=-1(요청 안 함)로 처리하면, scanner.py의 메인 루프(`if page.status_code
== -1: continue`)가 어떤 check도 그 페이지에 접근하지 못하게 걸러준다 — check마다 개별
가드를 반복할 필요가 없어짐 (단일 지점에서 방어).

⚠️ 배경 (is_unsafe_mutation_target이 왜 필요해졌는가):
GET은 안전하지만(크롤러가 계속 방문해도 되고, idor.py도 이 URL로 계속 조회 비교함),
그 페이지의 POST form에 SQLi/XSS/Stored XSS check가 실제로 payload를 제출하면 두 가지
문제가 생길 수 있다:
  a) /posts/edit/<id>, /vuln/posts/edit/<id>: 실제 게시글 title/content가 수정됨.
  b) /signup: 실제 계정이 생성됨. 이게 왜 문제냐면, SQLi payload 중 `' OR '1'='1`처럼
     signup의 비밀번호 길이 제한(8~20자)을 통과하는 값이 있으면 그 payload 자체가 그대로
     실제 비밀번호가 되는 계정이 만들어진다. 같은 스캔 안에서 나중에 /api/token,
     /vuln/rate-limit처럼 파라미터화된(=SQLi에 안전한) 쿼리를 쓰는 다른 엔드포인트를
     같은 payload로 테스트하면, 그 계정으로 "우연히 로그인 성공"해버려서 SQL Injection이
     아닌데도 취약점으로 오판된다 (실제로 재현 확인: /signup 퍼징 중 만들어진 'test'
     계정 때문에 /api/token, /vuln/rate-limit에서 SQL Injection 오탐 발생).
두 경우 다 GET 자체는 문제 없으므로 크롤러 차단(status_code=-1) 대상에는 넣지 않고,
"form에 실제로 POST"하는 check(sql_injection.py/xss.py/stored_xss.py)만 이 함수로
해당 form을 건너뛰도록 했다.
"""
from __future__ import annotations
from urllib.parse import urlparse

# 이 단어가 경로에 포함되면 실제 요청을 보내지 않음 (GET만으로 상태를 바꾸는 엔드포인트 방지)
DESTRUCTIVE_PATH_HINTS = ("delete", "remove", "drop")


def looks_destructive(url: str) -> bool:
    """URL 경로에 삭제 등 상태 변경 작업으로 보이는 단어가 포함돼 있는지 확인."""
    path = urlparse(url).path.lower()
    return any(hint in path for hint in DESTRUCTIVE_PATH_HINTS)


# GET으로 조회하는 것 자체는 안전하지만(IDOR 조회 비교에 계속 사용해도 됨), 이 경로의
# <form method="POST">에 실제로 payload를 제출하면 게시글 title/content가 실제로
# 수정된다. SQL Injection/XSS/Stored XSS처럼 "form에 실제로 POST"하는 check가 이
# form을 mutation 테스트 대상으로 쓰면 스캔 중 데이터가 바뀌어버리므로, 그 check들만
# 이 경로의 POST form을 건너뛰어야 한다 (crawler 단계에서 URL 자체를 막으면 안 됨 —
# 그러면 idor.py의 GET 기반 IDOR 확인 자체가 불가능해짐. delete류와 달리 GET은 안전).
# 이 프로젝트 Backend 기준: /posts/edit/<id>, /vuln/posts/edit/<id> 둘 다 여기 해당하며,
# 둘 다 경로에 "/posts/edit/"를 포함하므로 힌트 하나로 커버된다.
MUTATING_EDIT_FORM_PATH_HINTS = ("/posts/edit/",)


def is_mutating_edit_form(url: str) -> bool:
    """이 URL(주로 form.action)이, 실제로 POST하면 데이터를 수정하는 '게시글 수정'
    엔드포인트인지 확인. True면 SQLi/XSS/Stored XSS 같은 "form에 실제로 POST"하는
    check가 이 form을 건드리지 않아야 한다 — 조회용 GET(IDOR 등)에는 영향 없음."""
    path = urlparse(url).path.lower()
    return any(hint in path for hint in MUTATING_EDIT_FORM_PATH_HINTS)


# /signup의 POST form에 임의 payload를 제출하면 실제 계정이 생성된다. 이 계정이 이후
# 같은 스캔에서 다른 페이지(/api/token, /vuln/rate-limit 등)를 검사할 때 우연히
# "username=이때 넣은 문자열, password=이때 넣은 문자열"과 일치해버리면, SQL Injection이
# 아닌데도 "baseline은 실패, payload는 성공"으로 오판되는 오탐이 생긴다.
# (실제로 재현 확인: /signup 퍼징 중 생성된 'test' 계정 때문에, 파라미터화된 쿼리를 쓰는
# /api/token, /vuln/rate-limit에서 SQL Injection 오탐이 발생함 — payload가 SQL 조건절을
# 조작한 게 아니라, 그 payload 자체가 그 계정의 진짜 비밀번호였을 뿐.)
ACCOUNT_CREATING_FORM_PATH_HINTS = ("/signup",)


def creates_persistent_account(url: str) -> bool:
    """이 URL(주로 form.action)에 POST하면 실제 계정이 생성되는지 확인. True면 SQLi/XSS/
    Stored XSS 같은 "form에 실제로 POST"하는 check가 이 form을 건드리면 안 된다 — 계정
    생성 자체가 같은 스캔 내 다른 페이지 검사 결과를 오염시킬 수 있다."""
    path = urlparse(url).path.lower()
    return any(hint in path for hint in ACCOUNT_CREATING_FORM_PATH_HINTS)


def is_unsafe_mutation_target(url: str) -> bool:
    """SQLi/XSS/Stored XSS처럼 "form에 실제로 POST"하는 check가 이 URL의 form을 건드리면
    안 되는지 종합 판단 (is_mutating_edit_form 또는 creates_persistent_account 중 하나라도
    해당하면 True). 조회용 GET에는 영향 없다 — idor.py 등은 이 함수를 쓰지 않는다."""
    return is_mutating_edit_form(url) or creates_persistent_account(url)
