# Scanner (3주차)

URL 입력 → 크롤링 → 취약점 검사 → JSON 결과 저장 흐름의 파이프라인.
1주차(SQLi, XSS) + 2주차(Directory Traversal, Stored XSS, IDOR, Security Header)
+ 3주차(File Upload, JWT 검증, Authorization/Broken Authentication, Rate Limit) 검사 포함.

## 폴더 구조

```
Scanner/
├── scanner.py              # 메인 진입점 (CLI). 전체 파이프라인을 조립/실행
├── crawler.py               # requests + BeautifulSoup 기반 크롤러
├── auth.py                   # 로그인 세션 헬퍼 (idor, broken_authentication 등이 사용)
├── swagger_seed.py            # swagger.yaml/json에서 링크로 못 찾는 라우트(/vuln/* 등)를 뽑아 시드로 추가
├── checks/
│   ├── __init__.py           # 실행할 check 함수들을 등록하는 레지스트리
│   ├── base.py                # Finding, Severity, VULN_TYPE_MAP 등 공통 데이터 구조
│   ├── sql_injection.py       # 에러 기반 SQLi 탐지 (1주차)
│   ├── xss.py                  # 반사형 XSS 탐지 (1주차)
│   ├── directory_traversal.py  # 경로 조작 탐지 (2주차)
│   ├── stored_xss.py            # 저장형 XSS 탐지 (2주차)
│   ├── idor.py                   # 권한 검증 누락 / IDOR 탐지 (2주차)
│   ├── security_headers.py        # 보안 헤더 누락 탐지 (2주차)
│   ├── file_upload.py              # 파일 업로드 확장자 검증 누락 탐지 (3주차)
│   ├── jwt_verification.py          # JWT 서명 검증 누락 탐지 (3주차)
│   ├── broken_authentication.py      # 세션/로그인 인증 취약점 탐지 (3주차)
│   └── rate_limiting.py               # 요청 횟수 제한 누락 탐지 (3주차)
├── payloads/
│   ├── sql_injection.txt
│   ├── xss.txt
│   ├── directory_traversal.txt
│   ├── stored_xss.txt           # 참고용 (실제 payload는 코드에서 동적 생성)
│   ├── idor.txt                  # 테스트 계정 목록 (username:password)
│   ├── security_headers.txt      # 빈 파일 (payload 불필요)
│   ├── file_upload.txt            # 업로드 시도할 위험한 파일명 목록 (3주차)
│   ├── missing_jwt_verification.txt  # 빈 파일 (payload 불필요, 응답에서 토큰을 직접 찾음) (3주차)
│   ├── broken_authentication.txt      # 테스트 계정 (username:password) (3주차)
│   └── missing_rate_limiting.txt       # 빈 파일 (payload 불필요) (3주차)
├── results/                       # 스캔 결과 JSON이 저장되는 폴더 (scan_<타임스탬프>.json + latest.json, git 추적 안 함)
└── requirements.txt
```

## 각 파일의 역할

| 파일 | 역할 |
|---|---|
| `scanner.py` | CLI 인자 파싱 → `Crawler` 실행 → (옵션) swagger 시드 병합 → 각 `checks/*.run()` 호출 → 결과를 `results/*.json`에 저장 |
| `crawler.py` | 시작 URL부터 BFS로 같은 도메인 내 페이지를 순회하며 링크(`<a>`)와 폼(`<form>`)을 수집. `visit_extra()`로 임의 URL 1개를 결과에 추가할 수도 있음 |
| `auth.py` | 계정으로 로그인해서 세션 쿠키를 발급받는 헬퍼 (`checks/idor.py`, `checks/broken_authentication.py`가 사용) |
| `swagger_seed.py` | swagger.yaml/json을 읽어, `index.html`/`posts.html` 등에 링크가 없는 라우트(`/vuln/*`)를 크롤링 시드로 변환 |
| `checks/base.py` | 모든 check 모듈이 공유하는 `Finding`(발견 결과 1건) 데이터 클래스, `Severity` 등급 정의, 그리고 Report와 이름을 맞추기 위한 `VULN_TYPE_MAP`/`SEVERITY_DISPLAY_MAP` |
| `checks/sql_injection.py` | 쿼리 파라미터에 SQLi 페이로드를 넣고 응답에 DB 에러 시그니처가 있는지 확인 |
| `checks/xss.py` | 쿼리 파라미터에 XSS 페이로드를 넣고 응답에 이스케이프 없이 그대로 반사되는지 확인 |
| `checks/directory_traversal.py` | 쿼리 파라미터에 경로 조작 페이로드를 넣고 시스템 파일 노출 여부 확인 |
| `checks/stored_xss.py` | POST form에 고유 마커 payload를 제출한 뒤, 제출 페이지와 (매핑된) 확인 페이지를 재조회해서 이스케이프 없이 남는지 확인 |
| `checks/idor.py` | ID 기반 URL에 대해 인증 없이/계정 간 접근 가능 여부 확인. 삭제형 URL은 실제 요청을 보내지 않음(안전장치) |
| `checks/security_headers.py` | 응답 헤더에 CSP, X-Frame-Options 등 보안 헤더가 빠졌는지 확인 |
| `checks/file_upload.py` *(3주차)* | `input type="file"`이 있는 POST 폼에 위험한 확장자(.php, .jsp 등) 파일을 실제 업로드해서 검증 없이 수락되는지 확인 |
| `checks/jwt_verification.py` *(3주차)* | 응답(쿠키/바디/헤더)에서 JWT를 찾아 alg=none·서명 변조 토큰으로 재요청, 서명 검증 없이 통과되는지 확인 |
| `checks/broken_authentication.py` *(3주차)* | 로그인 페이지 대상, 세션 쿠키 보안 속성·토큰 예측 가능성·로그인 실패 횟수 제한(계정 잠금) 여부 확인 |
| `checks/rate_limiting.py` *(3주차)* | 로그인 등 민감 엔드포인트에 연속 요청을 보내 429/Retry-After 등 제한이 걸리는지 확인 |
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

결과는 `results/scan_<타임스탬프>.json`에 저장되며, 동시에 항상 최신 결과를 담은
`results/latest.json`도 같은 내용으로 덮어써집니다. Report/통합 담당은 매번 다른 타임스탬프
파일명을 찾을 필요 없이 `results/latest.json`만 보면 됩니다.

## ⚙️ Backend 쪽 실제 구조에 맞춰 넣은 설정값 (바뀌면 여기만 수정)

| 파일 | 상수 | 현재 값 | 의미 |
|---|---|---|---|
| `checks/stored_xss.py` | `REVISIT_URL_OVERRIDES` | `{"/posts": "/vuln/posts"}` | `/posts`에 글을 쓰면 `/vuln/posts`에서 이스케이프 없이 보여줌 (Backend가 확인 페이지를 바꾸면 여기 수정) |
| `checks/idor.py` | `DESTRUCTIVE_PATH_HINTS` | `("delete", "remove", "drop")` | 이 단어가 경로에 있으면 실제 요청을 보내지 않고 "발견"만 기록 (스캔 중 데이터 삭제 방지) |
| `checks/directory_traversal.py` | `SIGNATURES` | `/etc/passwd`, `win.ini` 기준 | `/vuln/download?file=`이 파일을 그대로 읽어 반환하므로 그대로 유효 |
| `auth.py` | `LOGIN_PATH` / `AUTH_CHECK_PATH` | `/login` / `/users` | 로그인 방식이 바뀌면 여기만 수정 (broken_authentication.py도 LOGIN_PATH를 그대로 사용) |
| `swagger_seed.py` | `DEFAULT_QUERY_PARAMS` | `{"/vuln/download": "file=test.txt"}` | swagger 스펙엔 없는, 테스트용 쿼리 파라미터 예시값 |
| `checks/file_upload.py` | `REJECT_HINTS` | `("허용되지 않는", ...)` | 업로드 거부 응답 문구가 바뀌면 여기 수정 (Backend/upload.py 기준) |
| `checks/rate_limiting.py` | `SENSITIVE_PATH_HINTS` | `("login","signin","signup","auth")` | 이 문자열이 경로에 포함된 페이지에서만 반복 요청 테스트를 실행 (서버 부하 방지) |
| `checks/base.py` | `VULN_TYPE_MAP` | Notion 매핑 그대로 | check_name → Report 표기 이름. Report의 `mitigation_guide.md` 표와 정확히 같은 문자열이어야 함 |

## ⚠️ 안전 관련 참고

`Backend/app.py`의 `/posts/delete/<id>`, `/vuln/posts/delete/<id>`는 **GET 요청 하나로 실제 삭제**가 실행되고 로그인 체크도 없습니다. `checks/idor.py`는 URL에 `delete`가 포함되면 자동으로 실제 요청을 생략하도록 되어 있지만, 다른 검사(`sql_injection`, `xss` 등)가 크롤링 중 이 URL을 우연히 건드릴 가능성은 배제하지 못하니, 테스트 서버에는 되돌릴 수 있는 더미 데이터만 넣어두는 걸 권장합니다.

## 결과 JSON 예시 구조 (3주차: Report 스키마에 맞춤)

⚙️ Report(`report_generator.py`)가 `target`, `scan_date`, `vulnerabilities`(각 항목의
`type`/`severity`/`url`/`evidence`/`description`)를 읽으므로, Scanner 출력도 이 이름을 그대로
사용합니다. (내부적으로는 `checks/*.py`가 여전히 `check_name`/소문자 `severity`로 `Finding`을
만들고, `Finding.to_dict()`(`checks/base.py`)가 출력 시점에 `type`/Capitalize로 변환합니다.)

```json
{
  "target": "http://localhost:5000",
  "scan_date": "2026-07-11T03:50:33+00:00",
  "pages_crawled": 14,
  "checks_run": ["sql_injection", "xss", "directory_traversal", "stored_xss", "idor", "security_headers", "file_upload", "missing_jwt_verification", "broken_authentication", "missing_rate_limiting"],
  "vulnerabilities_count": 3,
  "vulnerabilities": [
    {
      "type": "Directory Traversal",
      "url": "http://localhost:5000/vuln/download?file=../../../etc/passwd",
      "parameter": "file",
      "payload": "../../../etc/passwd",
      "severity": "High",
      "evidence": "응답에서 시스템 파일 노출 시그니처 발견: 'root:x:0:0'",
      "description": "파일 경로 파라미터가 검증 없이 사용되어, 서버 내 임의 파일에 접근할 수 있습니다."
    }
  ]
}
```

같은 내용이 `results/scan_<타임스탬프>.json`과 `results/latest.json`에 동시에 저장됩니다.

## 설계 포인트

- **check 함수 시그니처 통일**: `run(session, page, payloads) -> list[Finding]`
  → `scanner.py`는 어떤 취약점을 검사하는지 몰라도 동일한 방식으로 호출/집계 가능.
  → 새 검사를 추가할 때 `checks/`에 파일 하나, `payloads/`에 파일 하나, `checks/__init__.py`에 한 줄만 추가하면 됨.
- **개별 check 실패가 전체 스캔을 중단시키지 않도록** `scanner.py`에서 try/except로 방어.
- **크롤링 실패 페이지는 상태코드 `-1`로 기록**하고 검사 대상에서 제외.
- **링크로 못 찾는 라우트는 swagger로 보완**: 무조건 크롤링에 의존하지 않고, API 문서가 있으면 그걸 신뢰할 수 있는 시드 소스로 병행 사용.
- **파괴적(destructive) 엔드포인트는 실제로 실행하지 않고 "발견만" 기록**: 자동화된 스캔이 테스트 대상 데이터를 실제로 훼손하지 않도록 방어.

## 3주차: Scanner ↔ Report 스키마 불일치 해결 (완료)

Notion "안 맞는 부분 정리"에서 Scanner 담당으로 배정된 항목들:

- ✅ `findings` → `vulnerabilities`, `check_name` → `type` (Finding.to_dict() / scanner.py)
- ✅ check_name → Report 표기 이름 매핑 (`checks/base.py`의 `VULN_TYPE_MAP`, `mitigation_guide.md`와 동일한 문자열)
- ✅ severity Capitalize (`checks/base.py`의 `SEVERITY_DISPLAY_MAP`). 단, `info`는 Report의
  `SEVERITY_ORDER`에 아직 없어 "Info"로 표기는 하되 요약 카운트에는 안 잡힘 — **Info 등급을
  Report에 추가할지는 팀 결정 필요** (Notion에도 명시됨)
- ✅ `results/latest.json` 항상 최신 결과로 갱신 (타임스탬프 파일과 동시 저장)
- ✅ `file_upload` 검사 추가
- ✅ 3주차 신규 검사: `missing_jwt_verification`(JWT 검증), `broken_authentication`(Authorization/인증),
  `missing_rate_limiting`(Rate Limit)

아래는 Scanner 쪽에서 실제로 확인해본 결과, **다른 담당(Backend/Report/통합)의 몫으로 남아있는 항목**입니다 (Scanner 코드로는 해결 불가):

- `mitigation_guide.md`에 `security_headers` 검사에 대응하는 "Security Headers" 행이 아직 없음
  → Report 담당이 추가하기 전까지는 리포트에 "대응 방안 미정의"로 표시됨 (실제로 report_generator.py로 확인함)
- Backend가 `init_db.py` 하드코딩 제거 + DB 초기화 자동 실행을 해야 `docker-compose.yml`의
  Scanner가 정상적으로 Backend에 붙을 수 있음
- Scanner/Report가 결과 폴더(`results/`)를 공유하려면 통합 담당이 `docker-compose.yml`에
  공유 볼륨을 추가해야 함 (지금은 로컬 실행 시 `results/latest.json` 경로만 맞춰둔 상태)

## 아직 남은 것 (Backend 확인/요청 필요)

- `posts` 테이블에 소유자(`user_id`) 컬럼이 없어, IDOR은 "권한 검증 자체가 없다"까지만 탐지 가능. 실제 "내 것이 아닌 데이터 접근" 시나리오는 컬럼 추가 후 `checks/idor.py`의 `OWNER_FIELD_CANDIDATES` 부분을 확장하면 됨
- swagger.yaml이 정적 파일로만 존재 (서버 라우트로 노출 안 됨) — 지금은 로컬 파일 경로로 넘겨서 사용 중. 나중에 `/swagger.json` 같은 라우트로 노출되면 `--swagger` 값을 URL로 바꾸기만 하면 됨
- 현재 Backend(`app.py`)는 세션 쿠키 인증만 사용하고 JWT를 발급하지 않음 → `checks/jwt_verification.py`는
  실제로 JWT를 쓰는 백엔드(또는 3주차 이후 JWT가 도입된 API)를 스캔할 때 의미가 있음. 지금 Backend
  대상으로는 findings 0건이 정상 (별도 mini Flask 앱으로 alg=none/서명 변조 탐지 로직 자체는 검증 완료)
