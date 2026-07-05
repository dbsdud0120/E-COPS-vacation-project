# Scanner MVP (1주차)

URL 입력 → 크롤링 → 취약점 검사 → JSON 결과 저장 흐름의 최소 골격.

## 폴더 구조

```
scanner_mvp/
├── scanner.py              # 메인 진입점 (CLI). 전체 파이프라인을 조립/실행
├── crawler.py               # requests + BeautifulSoup 기반 크롤러
├── checks/
│   ├── __init__.py          # 실행할 check 함수들을 등록하는 레지스트리
│   ├── base.py               # Finding, Severity 등 공통 데이터 구조
│   ├── sql_injection.py      # 에러 기반 SQLi 탐지 (샘플 로직)
│   └── xss.py                 # 반사형 XSS 탐지 (샘플 로직)
├── payloads/
│   ├── sql_injection.txt      # SQLi 테스트 페이로드 목록
│   └── xss.txt                 # XSS 테스트 페이로드 목록
├── results/                    # 스캔 결과 JSON이 저장되는 폴더
└── requirements.txt
```

## 각 파일의 역할

| 파일 | 역할 |
|---|---|
| `scanner.py` | CLI 인자 파싱 → `Crawler` 실행 → 각 `checks/*.run()` 호출 → 결과를 `results/*.json`에 저장 |
| `crawler.py` | 시작 URL부터 BFS로 같은 도메인 내 페이지를 순회하며 링크(`<a>`)와 폼(`<form>`)을 수집 |
| `checks/base.py` | 모든 check 모듈이 공유하는 `Finding`(발견 결과 1건) 데이터 클래스와 `Severity` 등급 정의 |
| `checks/sql_injection.py` | 쿼리 파라미터에 SQLi 페이로드를 넣고 응답에 DB 에러 시그니처가 있는지 확인 (에러 기반 탐지) |
| `checks/xss.py` | 쿼리 파라미터에 XSS 페이로드를 넣고 응답에 이스케이프 없이 그대로 반사되는지 확인 |
| `checks/__init__.py` | `CHECK_REGISTRY` 딕셔너리로 "check 이름 → 실행 함수"를 매핑. 새 검사 추가 시 이 파일만 수정하면 됨 |
| `payloads/*.txt` | 각 check가 사용할 테스트 문자열 목록 (한 줄당 하나) |

## 실행 방법

```bash
pip install -r requirements.txt
python scanner.py https://target.example.com --depth 2 --checks sql_injection,xss
```

결과는 `results/scan_<타임스탬프>.json`에 저장됩니다.

## 결과 JSON 예시 구조

```json
{
  "target": "https://target.example.com",
  "scanned_at": "2026-07-02T03:50:33+00:00",
  "pages_crawled": 5,
  "checks_run": ["sql_injection", "xss"],
  "findings_count": 2,
  "findings": [
    {
      "check_name": "sql_injection",
      "url": "https://target.example.com/search?q=' OR '1'='1",
      "parameter": "q",
      "payload": "' OR '1'='1",
      "severity": "high",
      "evidence": "응답에서 SQL 에러 시그니처 발견: 'you have an error in your sql syntax'",
      "description": "입력값이 SQL 쿼리에 그대로 삽입되어 DB 에러가 노출될 가능성이 있습니다."
    }
  ]
}
```

## 설계 포인트

- **check 함수 시그니처 통일**: `run(session, page, payloads) -> list[Finding]`
  → `scanner.py`는 어떤 취약점을 검사하는지 몰라도 동일한 방식으로 호출/집계 가능.
  → 새 검사(예: CSRF, Open Redirect, 보안 헤더 누락 등)를 추가할 때 `checks/`에 파일 하나,
    `payloads/`에 파일 하나, `checks/__init__.py`에 한 줄만 추가하면 됨.
- **개별 check 실패가 전체 스캔을 중단시키지 않도록** `scanner.py`에서 try/except로 방어.
- **크롤링 실패 페이지는 상태코드 `-1`로 기록**하고 검사 대상에서 제외.

## 현재는 "틀"만 있는 부분 (다음 주차 TODO)

취약 서버가 아직 없어서 아래는 실제 검증 없이 구조만 잡아둔 상태입니다.

1. **`checks/sql_injection.py`**
   - `SIGNATURES` 목록을 실제 DB 에러 메시지로 보강
   - Blind/Time-based, Boolean-based 탐지 로직 추가
   - form(POST) 기반 실제 전송 로직 구현
2. **`checks/xss.py`**
   - 단순 문자열 포함 여부가 아니라 HTML 컨텍스트(속성/스크립트 등)별 반사 여부 구분
   - 저장형(Stored) XSS 시나리오 (제출 → 다른 페이지 재방문) 추가
   - form(POST) 기반 실제 전송 로직 구현
3. **`crawler.py`**
   - 로그인/세션이 필요한 페이지 처리
   - JS로 렌더링되는 링크 대응 (Playwright/Selenium 검토)
4. **공통**
   - 요청 속도 제한(rate limit) / 재시도 로직
   - 스캔 진행률 표시, 결과 요약 리포트(HTML) 생성
