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
├── Scanner/                    # 취약점 스캐너 엔진
│   ├── scanner.py              # 메인 스캐너 로직
│   ├── crawler.py              # 웹 크롤러
│   ├── checks/                 # 취약점별 진단 모듈
│   └── payloads/               # 취약점 진단용 페이로드
├── Report/                     # 리포트 및 대시보드 생성기
│   ├── report_generator.py     # 종합 리포트 생성기
│   ├── dashboard_generator.py  # 대시보드 HTML 생성기
│   ├── security_policy_checker.py # 보안 정책 점검기
│   └── mitigation_guide.md     # 취약점 완화/조치 가이드
└── Platform/                   # 플랫폼 프론트엔드/컨트롤러 (외부 노출 접점)
    ├── app.py                  # 플랫폼 백엔드
    └── templates/              # 대시보드 & 결과 뷰
```

---

## 시스템 구조

```
                        사용자
                           |
                           | HTTP 요청
                           ↓
              ┌────────────────────────┐
              │        Platform        │
              │   (Web UI + 제어 역할)  │
              └────────────────────────┘
                           |
             ┌─────────────┴─────────────┐
             |                           |
             | POST /scan                | POST /report
             ↓                           ↓
┌──────────────────────┐      ┌──────────────────────┐
│   Scanner Container  │      │   Report Container   │
│                      │      │                      │
│  scanner_server.py   │      │  report_server.py    │
│  (Flask API Server)  │      │  (Flask API Server)  │
│                      │      │                      │
└──────────┬───────────┘      └──────────┬───────────┘
           |                             |
           | 실행 요청                    | 실행 요청
           ↓                             ↓
┌──────────────────────┐      ┌──────────────────────┐
│     scanner.py       │      │ report_generator.py  │
│                      │      │                      │
│ - URL 크롤링         │      │ - JSON 분석          │
│ - SQL Injection 검사 │      │ - HTML 생성          │
│ - XSS 검사           │      │ - PDF 생성           │
│ - 결과 JSON 생성     │      │                      │
└──────────┬───────────┘      └──────────┬───────────┘
           |                             |
           |                             |
           └─────────────┬───────────────┘
                         ↓

              ┌─────────────────────┐
              │  scanner-results    │
              │    Docker Volume    │
              │                     │
              │  result.json        │
              │  report.html        │
              │  report.pdf         │
              └─────────────────────┘
                         |
                         ↓
                  Platform 제공

(scanner.py는 SQL Injection, XSS외에 다른 취약점 검사도 진행)
```
---

## 기술 스택

| 분야 | 기술 |
|------|------|
| Backend | Python, Flask |
| Database | MySQL |
| Scanner | Python, Requests, BeautifulSoup, Selenium |
| Report | Python, Pandas, ReportLab |
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

1. JWT (JSON Web Token) 점검 결과가 0건으로 나오는 경우
원인: JWT 취약점 점검 모듈은 스캔 대상 서비스가 인증 토큰 헤더(Authorization: Bearer <token>)나 JWT 쿠키를 실제로 사용하는 엔드포인트를 포함하고 있을 때 동작합니다.

안내: 진단 대상 서비스가 Session/Cookie 기반 인증을 사용하거나 토큰 인증 헤더가 전달되지 않은 경우, JWT 관련 취약점 항목은 0건으로 표기됩니다. 이는 스캐너 오류가 아닌 대상 시스템의 표준 동작에 따른 정상적인 결과입니다.

2. 수동 점검 (Manual) 항목 안내
보안 정책 점검 리포트의 일부 항목은 자동화 스캐너로 판별할 수 없는 영역(예: 비즈니스 로직 검증, 2차 인증 적용 여부 등)을 포함합니다.

이러한 항목은 Manual(수동 확인 필요) 상태로 분류되며, 보안 담당자가 직접 확인 및 검토해야 합니다.

3. 동적 크롤링 및 인증 세션 제약
Selenium 기반의 크롤러가 탑재되어 있으나, 과도하게 복잡한 자바스크립트(SPA) 기반 이벤트 페이지의 경우 일부 깊은 경로가 크롤링에서 누락될 수 있습니다.

폼 로그인 자동화가 설정되지 않은 경우, 로그인 이후의 비공개 엔드포인트에 대한 자동 진단 범위가 제한될 수 있습니다.
