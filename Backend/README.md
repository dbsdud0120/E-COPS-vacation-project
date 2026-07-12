# Backend MVP (Week 2)

Flask 기반의 EVulnScanner 백엔드입니다.

회원 관리, 게시판, 파일 업로드 기능과 함께 웹 취약점 학습을 위한 취약 API를 제공합니다.

## 폴더 구조

```text
Backend/
├── app.py                  # Flask 애플리케이션 진입점
├── upload.py               # 파일 업로드 기능(정상/취약 업로드)
├── init_db.py              # MySQL 테이블 생성 스크립트
├── swagger.yaml            # OpenAPI(Swagger) 명세
├── templates/              # HTML 템플릿
├── uploads/
│   ├── safe/               # 정상 업로드 파일 저장
│   └── vuln/               # 취약 업로드 파일 저장
└── README.md
```

## 각 파일의 역할

| 파일 | 역할 |
|------|------|
| app.py | Flask 서버 실행, 회원가입/로그인, 게시판 CRUD, 취약 API 제공 |
| upload.py | 정상 파일 업로드, 취약 파일 업로드 및 업로드 파일 조회 라우트 제공 |
| init_db.py | MySQL 데이터베이스 및 테이블 생성 |
| swagger.yaml | API 명세(OpenAPI 3.0) |
| templates/ | 화면 렌더링을 위한 HTML 파일 |
| uploads/ | 업로드된 파일 저장 디렉터리 |

## 구현 기능

### 사용자 기능

- 회원가입
- 로그인(Session)
- 로그아웃(Session 종료)
- 사용자 조회
- 현재 로그인 사용자 표시

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
- Stored XSS
- Directory Traversal
- IDOR
- File Upload

## 실행 방법

### Docker 환경

```bash
docker compose up --build
```

### Flask 실행

```bash
python app.py
```

## 설계 포인트

- Flask Blueprint를 사용하여 파일 업로드 기능을 `upload.py`로 분리
- 비밀번호는 Werkzeug를 이용해 해시하여 저장
- MySQL 연결 정보는 환경변수(`MYSQL_HOST`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DATABASE`)를 사용하며, 로컬 개발 환경에서는 기본값을 사용하여 실행 가능
- 로그인한 사용자를 세션(Session)으로 관리
- 게시글 수정/삭제는 작성자 본인만 가능하도록 권한 검사를 적용
- 게시글 작성 시 로그인한 사용자를 작성자로 자동 저장
- 정상 업로드와 취약 업로드를 서로 다른 디렉터리에 저장하여 관리
- 업로드된 파일을 조회할 수 있는 라우트를 제공하여 스캐너에서 업로드 이후 접근 여부까지 검증 가능

## 현재 구현 범위

현재 백엔드는 웹 취약점 실습 및 스캐너 연동을 위한 기능을 구현한 상태입니다.






