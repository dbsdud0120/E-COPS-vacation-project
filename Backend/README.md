# Backend (Week 4)

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

## Week 4 변경 사항

### 신규 추가

- Swagger UI 연동(`/swagger`)
- 테스트 계정 및 게시글 자동 생성(`init_db.py`)
- users.username UNIQUE 제약조건 추가

### 기능 개선

- init_db.py 실행 시 개발용 데이터베이스 초기화 후 테스트 데이터 자동 생성
- Swagger 문서를 브라우저에서 바로 확인 가능하도록 개선


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

## 취약점 시연 방법

| 취약점                    | 시연 방법                                                                                        |
| ---------------------- | -------------------------------------------------------------------------------------------- |
| SQL Injection          | `/vuln/login`에서 아이디 또는 비밀번호에 `' OR '1'='1`과 같은 SQL Injection Payload를 입력하여 로그인 시도            |
| Stored XSS             | 게시글 작성 페이지에서 내용에 `<script>alert('XSS')</script>`를 입력한 뒤 게시글을 다시 조회                           |
| Broken Authentication  | `/vuln/broken-auth`에서 여러 번 로그인을 시도하여 정상 로그인(`/login`)과 Rate Limit 적용 여부 비교                   |
| JWT Validation Missing | `/api/token`으로 JWT를 발급받은 뒤 `/vuln/profile`에 Authorization 헤더를 포함하여 요청하고, 변조된 토큰도 허용되는지 확인    |
| Rate Limit Missing     | `/vuln/rate-limit`에 동일한 로그인 요청을 반복 전송하여 요청 횟수 제한이 없는 것을 확인                                   |
| Directory Traversal    | `/vuln/download?file=../../../../etc/passwd` 또는 `../` 경로를 포함한 요청을 전송하여 상위 디렉터리 접근 여부 확인      |
| IDOR                   | 다른 사용자의 게시글 ID를 이용하여 `/vuln/posts/edit/{post_id}`에 접근하거나 수정 요청을 보내 권한 검증 여부 확인               |
| File Upload            | 취약 업로드 페이지에서 실행 가능한 파일(예: `.php`, `.jsp`) 또는 검증되지 않은 확장자의 파일을 업로드하여 정상 업로드와 비교               |
| Reflected XSS          | `/vuln/comment?text=<script>alert('XSS')</script>`와 같이 스크립트를 포함한 파라미터를 전달하여 화면에 그대로 출력되는지 확인 |

### 테스트용 계정

`init_db.py`를 실행하면 아래 테스트 계정과 게시글이 자동으로 생성됩니다.

| 아이디   | 비밀번호     |
| ----- | -------- |
| admin | 12345678 |
| test1 | 12345678 |
| user1 | 12345678 |

테스트 게시글도 함께 생성되므로 컨테이너 실행 직후 바로 기능 및 취약점 시연이 가능합니다.
