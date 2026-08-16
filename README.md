# Security Scanner Platform

## 프로젝트 소개

Security Scanner Platform은 취약한 웹 애플리케이션과 REST API를 자동으로 진단하고, 발견된 취약점을 분석하여 HTML/PDF 리포트를 생성하는 통합 보안 진단 플랫폼입니다.

---

## 프로젝트 목표

- 취약한 웹 서비스 및 REST API 구축
- 웹/API 자동 취약점 진단
- 진단 결과 분석 및 리포트 생성
- Docker Compose 기반 통합 실행 환경 구축

---

## Git branch

```
각 팀원별 branch에서 코드 작성 후 PR을 통해 리뷰하고 main에 통합

├── main                      # 최종 결과물
├── feature/backend           # 취약 웹 서비스 및 REST API
├── feature/scanner           # 웹/API 자동 진단 엔진
├── feature/report            # 결과 분석 및 리포트 생성
└── feature/devops            # Docker 및 통합
```

## Repository 구조

```
E-COPS-vacation-project-main/
├── docker-compose.yml          # 서비스 컨테이너 오케스트레이션 및 포트/Expose 설정
├── nginx.conf                  # Nginx 프록시 설정
├── Backend/                    # 진단 대상 웹 앱
│   ├── app.py                  # Flask 메인 서버
│   ├── init_db.py              # 데이터베이스 초기화
│   ├── upload.py               # 파일 업로드 핸들러
│   ├── swagger.yaml            # API 문서
│   └── templates/              # HTML 템플릿
├── Scanner/                    # 취약점 스캐너 엔진 → 상세: Scanner/README.md
│   ├── scanner.py              # 메인 진입점 (CLI), 전체 파이프라인 조립/실행
│   ├── crawler.py              # requests + BeautifulSoup 기반 크롤러
│   ├── auth.py                 # 로그인 세션 헬퍼
│   ├── swagger_seed.py         # swagger 문서 기반 크롤링 시드 보완
│   ├── checks/                 # 취약점별 진단 모듈 (SQLi, XSS, IDOR 등 총 10종)
│   ├── payloads/                # 취약점 진단용 페이로드 목록
│   └── results/                 # 스캔 결과 JSON (scan_<타임스탬프>.json, latest.json)
├── Report/                     # 리포트 및 대시보드 생성기 → 상세: Report/README.md
│   ├── report_generator.py     # 취약점 상세 리포트 생성 (HTML + PDF)
│   ├── dashboard_generator.py  # 등급별/유형별 요약 대시보드 생성 (Chart.js)
│   ├── security_policy_checker.py  # 보안 정책 자동 점검 (HTTPS, Security Header, CORS, JWT 만료 등)
│   ├── policy_report_generator.py  # 정책 점검 결과 HTML 렌더링
│   ├── report_server.py        # Platform과 통신하는 Flask API 서버 (5002번 포트)
│   ├── mitigation_guide.md     # 취약점 유형별 대응 방안표
│   └── severity_guide.md       # 위험도(Critical~Info) 분류 기준표
└── Platform/                   # 오케스트레이터 / 외부 노출 접점 → 상세: Platform/README.md
    ├── app.py                  # 스캔 요청 접수, Scanner·Report 호출, 진행 상태 관리
    ├── Dockerfile
    └── templates/               # index.html (요청 페이지), result.html (진행률/결과 페이지)

각 서비스의 세부 구현(엔드포인트, 실행 방법, 내부 로직)은 해당 디렉토리의 README를 참고하세요:
Platform/README.md · Scanner/README.md · Report/README.md · Backend/README.md
```

---

## 시스템 구조

```
사용자
                                |
                                | HTTP 요청 (스캔 대상 URL 입력)
                                ↓
                  ┌─────────────────────────┐
                  │         Nginx           │
                  │     (Reverse Proxy)      │
                  └────────────┬────────────┘
                                ↓
                  ┌─────────────────────────┐
                  │        Platform          │
                  │  (Flask, 오케스트레이터)  │
                  │  - job_id 발급/상태 관리  │
                  │  - 진행률·로그 스트리밍   │
                  └────┬───────────────┬─────┘
                       │               │
             POST /scan│               │POST /report
                       ↓               ↓
        ┌───────────────────┐   ┌───────────────────┐
        │  Scanner Container │   │  Report Container  │
        │     (:5001)        │   │      (:5002)       │
        │                    │   │                    │
        │  scanner.py        │   │  report_generator   │
        │  - 크롤링           │   │  dashboard_generator │
        │  - 10종 취약점 검사  │   │  security_policy_    │
        │    (SQLi/XSS/IDOR/  │   │    checker            │
        │     JWT/Rate Limit  │   │  policy_report_       │
        │     등)              │   │    generator          │
        │  - 결과 JSON 생성    │   │                    │
        └──────────┬─────────┘   └──────────┬─────────┘
                   │                         │
                   │      scan 결과 JSON      │
                   └────────────►────────────┘
                                │
                                ↓
                  ┌─────────────────────────┐
                  │  /app/results/<job_id>/  │
                  │                          │
                  │  scan.log                │
                  │  report.html / report.pdf │
                  │  dashboard.html           │
                  │  policy_report.html       │
                  └────────────┬────────────┘
                                │
                                ↓
                        Platform이 사용자에게
                       다운로드 링크로 제공

Scanner는 SQL Injection, XSS 외에도 Stored XSS, Directory Traversal, File Upload, IDOR, Security Headers, JWT 검증 누락, Broken Authentication, Rate Limiting까지 총 10종의 검사를 수행합니다. Report는 스캔 결과를 바탕으로 취약점 상세 리포트, 종합 대시보드, 보안 정책 점검 리포트 3종의 산출물을 생성합니다.
```
---

## 기술 스택

| 분야 | 기술 |
|------|------|
| Backend | Python, Flask |
| Database | MySQL |
| Scanner | Python, Requests, BeautifulSoup |
| Report | Python, Jinja2, Chart.js, ReportLab(PDF) |
| Container | Docker, Docker Compose |
| API | Swagger(OpenAPI) |

---

## 팀 역할

| 역할 | 담당 업무 |
|------|-----------|
| Backend | 취약 웹 서비스 및 REST API 개발 |
| Scanner | 웹/API 자동 취약점 진단 |
| Report | 결과 분석 및 HTML/PDF 리포트 생성 |
| DevOps | Docker Compose, GitHub 관리, 통합 및 배포 |

---

## 개발 진행 순서

1. 취약 웹 서비스 및 API 개발
2. Docker 기반 실행 환경 구성
3. Scanner를 통한 취약점 탐지
4. JSON 결과 저장
5. 결과 분석 및 위험도 분류
6. HTML/PDF 리포트 생성
7. 플랫폼 통합 및 배포

---

## 실행 방법 (Getting Started)

Docker Compose 환경을 통해 전체 시스템(Platform, Scanner, Report, Target Backend, DB)을 일괄 실행합니다.

### 1. 전제 조건 (Prerequisites)
- [Docker](https://www.docker.com/) 및 [Docker Compose](https://docs.docker.com/compose/) 설치 필수

### 2. 컨테이너 빌드 및 실행
프로젝트 루트 디렉토리에서 아래 명령어를 실행합니다.

```bash
# 전체 컨테이너 빌드 및 백그라운드 실행
docker-compose up -d --build

# 실행 상태 확인
docker-compose ps
```

---

## 취약점 진단 및 리포트 확인 흐름

1. 브라우저를 열고 Platform Web UI(http://localhost)에 접속합니다.

2. 진단할 대상 URL(http://vulnerable-backend:5000)을 입력하고 [스캔 시작] 버튼을 클릭합니다.

3. 스캐너가 크롤링 및 취약점 검사(SQLi, XSS 등)를 수행하고, 리포트 서버가 결과를 분석합니다.

4. 스캔이 완료되면 결과 페이지에서 3가지 종합 결과물을 확인 및 다운로드합니다:

- 종합 대시보드 (Dashboard): 등급별/유형별 취약점 통계 및 차트

- 취약점 상세 리포트 (HTML): 각 취약점별 상세 설명 및 대응 가이드

- 보안 정책 리포트(HTML): HTTP 헤더, TLS, 쿠키 설정 등 보안 정책 점검 결과

---

## 제약사항 및 FAQ (Limitations)

1. **JWT (JSON Web Token) 점검 결과가 0건으로 나오는 경우**
   - **원인:** JWT 취약점 점검 모듈은 스캔 대상 서비스가 인증 토큰 헤더(`Authorization: Bearer <token>`)나 JWT 쿠키를 실제로 사용하는 엔드포인트를 포함하고 있을 때 동작합니다.
   - **안내:** 진단 대상 서비스가 Session/Cookie 기반 인증을 사용하거나 토큰 인증 헤더가 전달되지 않은 경우, JWT 관련 취약점 항목은 0건으로 표기됩니다. 이는 스캐너 오류가 아닌 대상 시스템의 표준 동작에 따른 정상적인 결과입니다.

2. **수동 점검 (Manual) 항목 안내**
   - 보안 정책 점검 리포트의 일부 항목은 자동화 스캐너로 판별할 수 없는 영역(예: 비즈니스 로직 검증, 2차 인증 적용 여부 등)을 포함합니다.
   - 이러한 항목은 **Manual(수동 확인 필요)** 상태로 분류되며, 보안 담당자가 직접 확인 및 검토해야 합니다.

3. **크롤링 및 인증 세션 제약**
   - 현재 크롤러(crawler.py)는 requests + BeautifulSoup 기반으로 동작하며, 자바스크립트 렌더링이 필요한 SPA(Single Page Application) 페이지의 일부 깊은 경로는 크롤링      에서 누락될 수 있습니다. 이런 라우트는 Swagger 문서를 시드로 병행 제공(--swagger 옵션)해 보완할 수 있습니다.
   - 폼 로그인 자동화가 설정되지 않은 경우, 로그인 이후의 비공개 엔드포인트에 대한 자동 진단 범위가 제한될 수 있습니다.

4. **로그인 계정 잠금(Rate Limit) 및 재스캔 대기 시간 안내**
   - **원인:** 대상 시스템의 로그인 엔드포인트(`/login`)에는 무차별 대입 공격(Brute Force)을 방지하기 위한 보안 정책이 적용되어 있습니다. 스캔 과정에서 인증 테스트 등으로 5회 이상 로그인 실패 시, 해당 계정은 30초 동안 자동 잠금 처리됩니다.
   - **안내:** 스캔 직후 동일 계정으로 재스캔(Re-scan)을 실행하면, 이전 잠금이 만료되지 않아 인증이 차단되고 오탐지(False Positive)가 발생할 수 있습니다. 따라서 **재스캔 수행 시에는 반드시 최소 30초 이상의 대기 시간을 가진 후 진행**해야 정상적인 세션 획득 및 진단이 가능합니다.
