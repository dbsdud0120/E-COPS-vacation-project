# Report (6주차)

Scanner가 생성한 취약점 스캔 결과(JSON)를 읽어, 사람이 보는 HTML/PDF 리포트와
대시보드, 보안 정책 점검 리포트로 변환하는 모듈입니다.

---

## 폴더 구조

Report/
├── report_generator.py          # 취약점 상세 리포트 생성 (HTML + PDF)
├── dashboard_generator.py       # 등급별/유형별 요약 대시보드 생성 (Chart.js)
├── security_policy_checker.py   # 대상 서버에 실제 요청을 보내 보안 정책 자동 점검
├── policy_report_generator.py   # security_policy_checker.py 결과를 HTML로 렌더링
├── report_server.py             # (통합담당 작성) 위 스크립트들을 API로 호출하는 Flask 서버
├── mitigation_guide.md          # 취약점 유형별 대응 방안표
├── severity_guide.md            # 위험도(Critical~Info) 분류 기준표
├── requirements.txt              # 의존 패키지 목록
├── assets/
│   ├── logo_base64.txt          # 팀 로고 (base64 인라인 임베드용)
│   └── chart.umd.js             # Chart.js 라이브러리 (CDN 의존 제거용 인라인 내장)
└── sample_result.json           # 로컬 테스트용 샘플 스캔 결과 (실제 제출용 X)

---

## 파일별 역할

| 파일 | 역할 |
|---|---|
| report_generator.py | Scanner 결과 JSON + mitigation_guide.md를 읽어, 취약점별 상세 카드(설명/증거/대응방안/비즈니스 영향/컴플라이언스 관점)로 구성된 HTML·PDF 리포트 생성 |
| dashboard_generator.py | 같은 JSON을 읽어 등급별 개수, 유형별 개수를 Chart.js 그래프로 시각화한 요약 대시보드 생성 |
| security_policy_checker.py | 대상 URL에 직접 HTTP 요청을 보내 HTTPS 강제, Security Header, CORS, JWT 만료시간 등을 자동 점검하고 결과를 JSON으로 저장 |
| policy_report_generator.py | 위 점검 결과 JSON을 Pass/Fail/Warning/Manual 배지가 붙은 HTML로 렌더링 |
| report_server.py | Platform이 POST /report로 결과 파일 경로를 보내면, 위 스크립트들을 순서대로 실행해 리포트/대시보드/정책 리포트를 만들어주는 API 서버 (5002번 포트) |

---

## 실행 방법

### 단독 실행 (로컬 테스트)

pip install -r requirements.txt

# 상세 리포트
python3 report_generator.py latest.json report .

# 대시보드
python3 dashboard_generator.py latest.json dashboard .

# 보안 정책 점검 (대상 서버가 실행 중이어야 함)
python3 security_policy_checker.py http://test-server.local policy_result.json
python3 policy_report_generator.py policy_result.json policy_report

### Platform 연동 (Docker 환경)

python3 report_server.py

Platform이 POST /report 요청(json_path, url, policy_path 포함)을 보내면
자동으로 상세 리포트/대시보드/정책 리포트를 생성하고,
results.report / results.dashboard / results.policy 형태로 응답합니다.

---

## Scanner ↔ Report 스키마

{
  "target": "http://test-server.local",
  "scan_date": "2026-07-19",
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "url": "/login",
      "severity": "Critical",
      "evidence": "...",
      "description": "..."
    }
  ]
}

- report_generator.py는 구버전 Scanner 출력(findings/check_name/소문자 severity)도
  자동으로 인식해서 위 형식으로 변환하도록 되어 있어, 스키마가 바뀌어도 안전합니다.
- type 값은 mitigation_guide.md의 항목명과 정확히 일치해야 대응 방안이 매칭됩니다.
  (Scanner의 checks/base.py의 VULN_TYPE_MAP과 1:1 대응 확인 완료 — 10개 항목 전부 일치)

---

## 위험도 기준 (severity_guide.md)

| 등급 | 기준 |
|---|---|
| Critical | 인증 우회 또는 시스템 전체 장악 가능 |
| High | 민감정보 노출 또는 권한 상승 가능 |
| Medium | 사용자 상호작용이 필요한 공격 |
| Low | 직접적 피해보다는 공격 가능성을 높이는 수준 |
| Info | 즉각적인 위험은 없으나 보안 강화 참고가 필요한 수준 |

---

## 주차별 변경 사항

### 1주차
- Scanner 결과 형식을 미리 정의한 sample_result.json 작성
- 위험도 4단계 기준표(severity_guide.md), 대응방안표(mitigation_guide.md) 작성
- 취약점 유형명을 영문으로 통일, JWT 관련 severity를 기준표에 맞춰 Critical로 수정

### 2주차
- report_generator.py: JSON → HTML/PDF 상세 리포트 자동 생성 기능 구현
- dashboard_generator.py: 등급별/유형별 Chart.js 대시보드 구현 (선택 기능)
- security_policy_checker.py / policy_report_generator.py: HTTPS·Security Header·CORS·JWT 만료시간 자동 점검 기능 구현 (선택 기능)
- mitigation_guide.md에 Security Headers 대응 방안 행 추가

### 3주차
- Scanner의 실제 출력 스키마(findings/check_name/소문자 severity)를 표준 스키마로 자동 변환하는 로직 추가
- Jinja2 autoescape=True 적용 — evidence/description에 <script> 등이 들어와도 실행되지 않고 문자로만 표시되도록 XSS 방지
- 각 취약점 카드에 비즈니스 영향, 컴플라이언스 관점 설명 추가
- SEVERITY_ORDER/SEVERITY_COLOR에 Info 등급 추가 (Scanner의 Severity.INFO와 매칭)
- 리포트 배경 테마를 다크 → 화이트 톤으로 변경

### 4주차
- 리포트 디자인을 Google Analytics 스타일 구조로 개편
  - 인덱스 탭("Summary"), 연속형 통계 줄(세로 구분선 방식), 볼드/일반 텍스트로 위계 구분
  - 필드 레이블 전부 영문화 (Description/Evidence/Mitigation/Business Impact/Compliance Perspective)
- 팀 브랜딩 추가: 로고(배경 투명 처리 후 base64 인라인 임베드) + 팀원 이름(김수현·이아서·나윤영·박소민) 헤더/푸터 표시
- report_generator.py에 Google Fonts(Noto Sans KR) import 추가 — 폰트 미설치 환경에서도 한글 깨짐 방지

### 5주차
- report_server.py(통합담당 작성)의 policy_path 처리 흐름을 최신 버전으로 정리
  - policy_path를 "미리 존재해야 하는 입력 파일"이 아닌 "checker가 생성하는 출력 경로"로 처리하도록 순서 수정
  - 응답 키를 policy_report → policy로 통일 (Platform의 다운로드 버튼 연동 기준과 일치)
  - subprocess 호출을 sys.executable로 통일, "python"과 sys.executable이 같이 들어가는 버그 수정
- 통합담당·Scanner 팀원과 report_server.py / VULN_TYPE_MAP 정합성 교차 확인

### 6주차
- 대시보드 그래프가 표시되지 않던 문제 해결
  - 1차 원인: Chart.js를 외부 CDN에서 불러오고 있어, 외부 네트워크가 제한된 환경에서 라이브러리 자체를 못 받아옴 → Chart.js 라이브러리를 assets/chart.umd.js로 로컬 내장하여 외부 요청 없이 항상 렌더링되도록 수정
  - 2차 원인(핵심 원인): Jinja2 autoescape가 <script> 안에 삽입되는 JSON의 따옴표를 HTML 엔티티(&#34;)로 변환해 자바스크립트 문법이 깨짐 → _safe_json() 헬퍼 도입, 5개 JSON 변수에 |safe 필터 적용하여 해결. 동시에 "</script>" 문자열을 통한 스크립트 태그 조기 종료 공격도 함께 방지 (HTML 본문에 들어가는 필드는 기존 autoescape 그대로 유지해 XSS 방지 유지)
  - Node.js 문법 검증 및 악성 페이로드 삽입 테스트로 수정 결과 확인
  - Chart.js 캔버스가 flex 레이아웃에서 높이 0으로 렌더링되는 문제 방지를 위해 명시적 높이 wrapper 적용
- requirements.txt에 pyjwt 추가 검토 (JWT 만료 점검 기능을 실제로 켤 때 필요)

---


- Platfo /scan → /report 흐름에서 정책 점검이 실제로 자동 트리거되는지 통합 테스트
- severity_guide.md와 코드(SEVERITY_ORDER)가 항상 동기화되도록 문서 관리
