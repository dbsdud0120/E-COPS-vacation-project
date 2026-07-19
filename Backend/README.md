# Backend (Week 3)

Flask 기반의 EVulnScanner 백엔드입니다.

회원 관리, 게시판, 파일 업로드 기능과 함께 웹 취약점 학습을 위한 취약 API를 제공합니다.

---

## 폴더 구조

```text
Backend/
├── app.py                  # Flask 애플리케이션 진입점
├── upload.py               # 파일 업로드 기능(정상/취약 업로드)
├── init_db.py              # MySQL 테이블 생성 스크립트
├── swagger.yaml            # OpenAPI(Swagger) 명세
├── entrypoint.sh           # DB 초기화 후 Flask 실행
├── templates/              # HTML 템플릿
├── uploads/
│   ├── safe/               # 정상 업로드 파일 저장
│   └── vuln/               # 취약 업로드 파일 저장
└── README.md
```

---

## 각 파일의 역할

| 파일 | 역할 |
|------|------|
| app.py | Flask 서버 실행, 회원가입/로그인, 게시판 CRUD, 취약 API 제공 |
| upload.py | 정상 파일 업로드, 취약 파일 업로드 및 업로드 파일 조회 라우트 제공 |
| init_db.py | MySQL 데이터베이스 및 테이블 생성 |
| entrypoint.sh | 컨테이너 실행 시 DB 초기화 후 Flask 실행 |
| swagger.yaml | API 명세(OpenAPI 3.0) |
| templates/ | 화면 렌더링을 위한 HTML 파일 |
| uploads/ | 업로드된 파일 저장 디렉터리 |

---

## 구현 기능

### 사용자 기능

- 회원가입
- 로그인(Session)
- 로그아웃(Session 종료)
- 사용자 조회
- 현재 로그인 사용자 표시
- JWT 발급 API
- 회원가입 입력값 검증
  - 아이디 길이 제한
  - 비밀번호 길이 제한
  - 아이디 형식(영문, 숫자, _) 검증
- 정상 로그인 Rate Limit 적용

### 게시판 기능

- 게시글 생성(Create)
- 게시글 조회(Read)
- 게시글 수정(Update)
- 게시글 삭제(Delete)
- 게시글 검색
- 작성자 본인만 수정/삭제 가능(권한 확인)

### 파일 업로드

- 정상 파일 업로드
- 취약 파일 업로드(확장자 및 파일명 검증 미적용)
- 업로드 파일 조회
- 정상/취약 업로드 저장 경로 분리

### 취약점 실습 API

- SQL Injection
- Broken Authentication
- JWT Validation Missing
- Rate Limit Missing
- Stored XSS
- Directory Traversal
- IDOR
- File Upload

---

## Week 3 변경 사항

### 신규 추가

- JWT 발급 API(`/api/token`)
- JWT Validation Missing 취약 API(`/vuln/profile`)
- Broken Authentication 취약 API(`/vuln/broken-auth`)
- Rate Limit Missing 취약 API(`/vuln/rate-limit`)
- Docker 실행 시 DB 자동 초기화를 위한 `entrypoint.sh`

### 기능 개선

- 회원가입 입력값 검증 추가
  - 아이디 길이 제한(4~20자)
  - 비밀번호 길이 제한(8~20자)
  - 아이디 형식(영문, 숫자, `_`) 검증

- 정상 로그인(`/login`)에 Rate Limit 적용
  - 로그인 실패 횟수 제한
  - 일정 횟수 초과 시 일정 시간 로그인 차단

- `init_db.py`를 환경변수(`MYSQL_HOST`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DATABASE`)를 사용하도록 수정

### Docker 개선

- 컨테이너 실행 시 `init_db.py`를 먼저 실행한 뒤 Flask 서버가 실행되도록 변경

---

## 실행 방법

### Docker 환경

```bash
docker compose up --build
```

### Flask 실행

```bash
python app.py
```

---

## 설계 포인트

- Flask Blueprint를 사용하여 파일 업로드 기능을 `upload.py`로 분리
- 비밀번호는 Werkzeug를 이용해 해시하여 저장
- MySQL 연결 정보는 환경변수(`MYSQL_HOST`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DATABASE`)를 사용하며, 로컬 개발 환경에서는 기본값을 사용하여 실행 가능
- 컨테이너 실행 시 `entrypoint.sh`를 통해 DB 초기화를 수행한 뒤 Flask 서버를 실행
- 로그인한 사용자를 Session으로 관리
- JWT 발급 API를 제공
- 회원가입 시 아이디 길이, 비밀번호 길이 및 아이디 형식을 검증
- 정상 로그인에는 Rate Limit을 적용하고, 취약 API에서는 이를 제거하여 비교 실습이 가능하도록 구현
- JWT Validation Missing, Broken Authentication 등 인증 관련 취약점을 별도 API로 제공
- 게시글 수정/삭제는 작성자 본인만 가능하도록 권한 검사를 적용
- 게시글 작성 시 로그인한 사용자를 작성자로 자동 저장
- 정상 업로드와 취약 업로드를 서로 다른 디렉터리에 저장하여 관리
- 업로드된 파일을 조회할 수 있는 라우트를 제공하여 스캐너에서 업로드 이후 접근 여부까지 검증 가능

---

## 현재 구현 범위

현재 백엔드는 회원 관리, 게시판, 파일 업로드 기능과 함께 다음 취약점 실습 API를 제공합니다.

- SQL Injection
- Broken Authentication
- JWT Validation Missing
- Rate Limit Missing
- Stored XSS
- Directory Traversal
- IDOR
- File Upload

또한 EVulnScanner 스캐너와 연동하여 취약점 탐지 및 결과 분석이 가능하도록 구현되어 있습니다.