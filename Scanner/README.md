# Scanner (2주차)

URL 입력 → 크롤링 → 취약점 검사 → JSON 결과 저장 흐름의 파이프라인.
1주차(SQLi, XSS) + 2주차(Directory Traversal, Stored XSS, IDOR, Security Header) 검사 포함.

## 폴더 구조

```
Scanner/
├── scanner.py              # 메인 진입점 (CLI). 전체 파이프라인을 조립/실행
├── crawler.py               # requests + BeautifulSoup 기반 크롤러
├── auth.py                   # 로그인 세션 헬퍼 (idor 등 인증이 필요한 검사에서 사용)
├── swagger_seed.py            # swagger.yaml/json에서 링크로 못 찾는 라우트(/vuln/* 등)를 뽑아 시드로 추가
├── checks/
│   ├── __init__.py           # 실행할 check 함수들을 등록하는 레지스트리
│   ├── base.py                # Finding, Severity 등 공통 데이터 구조
│   ├── sql_injection.py       # 에러 기반 SQLi 탐지 (1주차)
│   ├── xss.py                  # 반사형 XSS 탐지 (1주차)
│   ├── directory_traversal.py  # 경로 조작 탐지 (2주차)
│   ├── stored_xss.py            # 저장형 XSS 탐지 (2주차)
│   ├── idor.py                   # 권한 검증 누락 / IDOR 탐지 (2주차)
│   └── security_headers.py        # 보안 헤더 누락 탐지 (2주차)
├── payloads/
│   ├── sql_injection.txt
│   ├── xss.txt
│   ├── directory_traversal.txt
│   ├── stored_xss.txt           # 참고용 (실제 payload는 코드에서 동적 생성)
│   ├── idor.txt                  # 테스트 계정 목록 (username:password)
│   └── security_headers.txt      # 빈 파일 (payload 불필요)
├── results/                       # 스캔 결과 JSON이 저장되는 폴더
└── requirements.txt
```

## 각 파일의 역할

| 파일 | 역할 |
|---|---|
| `scanner.py` | CLI 인자 파싱 → `Crawler` 실행 → (옵션) swagger 시드 병합 → 각 `checks/*.run()` 호출 → 결과를 `results/*.json`에 저장 |
| `crawler.py` | 시작 URL부터 BFS로 같은 도메인 내 페이지를 순회하며 링크(`<a>`)와 폼(`<form>`)을 수집. `visit_extra()`로 임의 URL 1개를 결과에 추가할 수도 있음 |
| `auth.py` | 계정으로 로그인해서 세션 쿠키를 발급받는 헬퍼 (`checks/idor.py`가 사용) |
| `swagger_seed.py` | swagger.yaml/json을 읽어, `index.html`/`posts.html` 등에 링크가 없는 라우트(`/vuln/*`)를 크롤링 시드로 변환 |
| `checks/base.py` | 모든 check 모듈이 공유하는 `Finding`(발견 결과 1건) 데이터 클래스와 `Severity` 등급 정의 |
| `checks/sql_injection.py` | 쿼리 파라미터에 SQLi 페이로드를 넣고 응답에 DB 에러 시그니처가 있는지 확인 |
| `checks/xss.py` | 쿼리 파라미터에 XSS 페이로드를 넣고 응답에 이스케이프 없이 그대로 반사되는지 확인 |
| `checks/directory_traversal.py` | 쿼리 파라미터에 경로 조작 페이로드를 넣고 시스템 파일 노출 여부 확인 |
| `checks/stored_xss.py` | POST form에 고유 마커 payload를 제출한 뒤, 제출 페이지와 (매핑된) 확인 페이지를 재조회해서 이스케이프 없이 남는지 확인 |
| `checks/idor.py` | ID 기반 URL에 대해 인증 없이/계정 간 접근 가능 여부 확인. 삭제형 URL은 실제 요청을 보내지 않음(안전장치) |
| `checks/security_headers.py` | 응답 헤더에 CSP, X-Frame-Options 등 보안 헤더가 빠졌는지 확인 |
| `checks/__init__.py` | `CHECK_REGISTRY` 딕셔너리로 "check 이름 → 실행 함수"를 매핑. 새 검사 추가 시 이 파일만 수정하면 됨 |
| `payloads/*.txt` | 각 check가 사용할 테스트 문자열 목록 (한 줄당 하나) |

## 실행 방법

```bash
pip install -r requirements.txt

# 기본 (크롤링으로 찾은 페이지만 검사)
python scanner.py http://localhost:5000 --depth 2

# swagger 문서를 같이 넘기면, 링크 없는 /vuln/* 라우트도 찾아서 검사
python scanner.py http://localhost:5000 --swagger ../Backend/swagger.yaml

# 특정 검사만 실행
python scanner.py http://localhost:5000 --checks idor,security_headers
```

결과는 `results/scan_<타임스탬프>.json`에 저장됩니다.

## ⚙️ Backend 쪽 실제 구조에 맞춰 넣은 설정값 (바뀌면 여기만 수정)

| 파일 | 상수 | 현재 값 | 의미 |
|---|---|---|---|
| `checks/stored_xss.py` | `REVISIT_URL_OVERRIDES` | `{"/posts": "/vuln/posts"}` | `/posts`에 글을 쓰면 `/vuln/posts`에서 이스케이프 없이 보여줌 (Backend가 확인 페이지를 바꾸면 여기 수정) |
| `checks/idor.py` | `DESTRUCTIVE_PATH_HINTS` | `("delete", "remove", "drop")` | 이 단어가 경로에 있으면 실제 요청을 보내지 않고 "발견"만 기록 (스캔 중 데이터 삭제 방지) |
| `checks/directory_traversal.py` | `SIGNATURES` | `/etc/passwd`, `win.ini` 기준 | `/vuln/download?file=`이 파일을 그대로 읽어 반환하므로 그대로 유효 |
| `auth.py` | `LOGIN_PATH` / `AUTH_CHECK_PATH` | `/login` / `/users` | 로그인 방식이 바뀌면 여기만 수정 |
| `swagger_seed.py` | `DEFAULT_QUERY_PARAMS` | `{"/vuln/download": "file=test.txt"}` | swagger 스펙엔 없는, 테스트용 쿼리 파라미터 예시값 |

## ⚠️ 안전 관련 참고

`Backend/app.py`의 `/posts/delete/<id>`, `/vuln/posts/delete/<id>`는 **GET 요청 하나로 실제 삭제**가 실행되고 로그인 체크도 없습니다. `checks/idor.py`는 URL에 `delete`가 포함되면 자동으로 실제 요청을 생략하도록 되어 있지만, 다른 검사(`sql_injection`, `xss` 등)가 크롤링 중 이 URL을 우연히 건드릴 가능성은 배제하지 못하니, 테스트 서버에는 되돌릴 수 있는 더미 데이터만 넣어두는 걸 권장합니다.

## 결과 JSON 예시 구조

```json
{
  "target": "http://localhost:5000",
  "scanned_at": "2026-07-11T03:50:33+00:00",
  "pages_crawled": 14,
  "checks_run": ["sql_injection", "xss", "directory_traversal", "stored_xss", "idor", "security_headers"],
  "findings_count": 3,
  "findings": [
    {
      "check_name": "directory_traversal",
      "url": "http://localhost:5000/vuln/download?file=../../../etc/passwd",
      "parameter": "file",
      "payload": "../../../etc/passwd",
      "severity": "high",
      "evidence": "응답에서 시스템 파일 노출 시그니처 발견: 'root:x:0:0'",
      "description": "파일 경로 파라미터가 검증 없이 사용되어, 서버 내 임의 파일에 접근할 수 있습니다."
    }
  ]
}
```

## 설계 포인트

- **check 함수 시그니처 통일**: `run(session, page, payloads) -> list[Finding]`
  → `scanner.py`는 어떤 취약점을 검사하는지 몰라도 동일한 방식으로 호출/집계 가능.
  → 새 검사를 추가할 때 `checks/`에 파일 하나, `payloads/`에 파일 하나, `checks/__init__.py`에 한 줄만 추가하면 됨.
- **개별 check 실패가 전체 스캔을 중단시키지 않도록** `scanner.py`에서 try/except로 방어.
- **크롤링 실패 페이지는 상태코드 `-1`로 기록**하고 검사 대상에서 제외.
- **링크로 못 찾는 라우트는 swagger로 보완**: 무조건 크롤링에 의존하지 않고, API 문서가 있으면 그걸 신뢰할 수 있는 시드 소스로 병행 사용.
- **파괴적(destructive) 엔드포인트는 실제로 실행하지 않고 "발견만" 기록**: 자동화된 스캔이 테스트 대상 데이터를 실제로 훼손하지 않도록 방어.

## 아직 남은 것 (Backend 확인/요청 필요)

- DB 접속 정보(`docker-compose.yml` / `Backend/app.py` / `Backend/init_db.py`)가 서로 달라 서버가 정상 기동되지 않을 수 있음 — 통일 요청함
- `posts` 테이블에 소유자(`user_id`) 컬럼이 없어, IDOR은 "권한 검증 자체가 없다"까지만 탐지 가능. 실제 "내 것이 아닌 데이터 접근" 시나리오는 컬럼 추가 후 `checks/idor.py`의 `OWNER_FIELD_CANDIDATES` 부분을 확장하면 됨
- swagger.yaml이 정적 파일로만 존재 (서버 라우트로 노출 안 됨) — 지금은 로컬 파일 경로로 넘겨서 사용 중. 나중에 `/swagger.json` 같은 라우트로 노출되면 `--swagger` 값을 URL로 바꾸기만 하면 됨
