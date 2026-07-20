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
security-scanner-platform/
├── Backend/
├── Scanner/
├── Report/
├── docker-compose.yml
└── README.md
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
