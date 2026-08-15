# EVulnScanner Backend

Flask와 MySQL 기반으로 구현된 EVulnScanner의 취약 웹 서비스 및 REST API입니다.

회원 관리, 게시판, 파일 업로드 기능을 제공하며, 웹 보안 취약점의 탐지 원리와 정상적인 보안 처리를 비교·학습할 수 있도록 정상 라우트와 취약 라우트를 분리하여 구현했습니다.

---

## 주요 기술

* Python
* Flask
* MySQL
* PyMySQL
* Jinja2
* Werkzeug
* JWT
* Swagger UI / OpenAPI 3.0
* Docker / Docker Compose

---

## 폴더 구조

```text
Backend/
├── app.py                  # Flask 애플리케이션 진입점
├── upload.py               # 정상/취약 파일 업로드 기능
├── init_db.py              # MySQL 테이블 및 테스트 데이터 초기화
├── swagger.yaml            # OpenAPI 명세
├── entrypoint.sh           # DB 초기화 후 Flask 실행
├── Dockerfile              # Backend 컨테이너 이미지 설정
├── requirements.txt        # Python 패키지 목록
├── templates/              # HTML 템플릿
├── uploads/
│   ├── safe/               # 정상 업로드 파일 저장
│   └── vuln/               # 취약 업로드 파일 저장
└── README.md
```

---

## 파일별 역할

| 파일 또는 디렉터리         | 역할                                         |
| ------------------ | ------------------------------------------ |
| `app.py`           | Flask 서버 실행, 회원가입·로그인, 게시판 및 취약점 실습 API 제공 |
| `upload.py`        | 정상/취약 파일 업로드와 업로드 파일 조회 기능 제공              |
| `init_db.py`       | MySQL 테이블 생성 및 시연용 테스트 데이터 등록              |
| `entrypoint.sh`    | 컨테이너 시작 시 DB 초기화 후 Flask 애플리케이션 실행         |
| `swagger.yaml`     | OpenAPI 3.0 기반 API 명세                      |
| `Dockerfile`       | Backend Docker 이미지 빌드 설정                   |
| `requirements.txt` | Backend 실행에 필요한 Python 패키지 관리              |
| `templates/`       | 웹 화면 렌더링에 사용하는 HTML 템플릿                    |
| `uploads/safe/`    | 검증을 통과한 정상 업로드 파일 저장                       |
| `uploads/vuln/`    | 취약 업로드 기능으로 등록된 파일 저장                      |

---

## 구현 기능

### 사용자 관리

* 회원가입
* 로그인 및 로그아웃
* Session 기반 로그인 상태 관리
* 현재 로그인 사용자 표시
* 사용자 목록 조회 시 인증 확인
* 비밀번호 해시 저장
* JWT 발급 API
* 회원가입 입력값 검증

  * 아이디 4~20자 제한
  * 영문, 숫자, `_`만 허용
  * 비밀번호 8~20자 제한
* 정상 로그인 Rate Limit 적용

  * 로그인 실패 횟수 제한
  * 일정 시간 동안 로그인 잠금

### 게시판

* 게시글 생성
* 게시글 목록 및 상세 조회
* 게시글 검색
* 게시글 수정
* 게시글 삭제
* 게시글 작성 시 로그인 사용자의 `username`과 `user_id` 저장
* `user_id` 기반 작성자 권한 검증
* 작성자 본인만 정상 게시글 수정 및 삭제 가능
* 정상 게시판과 IDOR 취약 게시판 분리

### 파일 업로드

* 허용 확장자를 검사하는 정상 파일 업로드
* `secure_filename()`을 이용한 안전한 파일명 처리
* 확장자와 파일명 검증이 미흡한 취약 파일 업로드
* 정상/취약 업로드 저장 경로 분리
* 업로드 파일 메타데이터 DB 저장
* 업로드한 사용자 `user_id` 저장
* 업로드 파일 접근 및 다운로드 기능

### API 문서

* OpenAPI 3.0 기반 API 명세 제공
* Swagger UI를 통한 API 확인 및 테스트
* 요청 파라미터, JWT Header 및 응답 예시 제공

Swagger UI는 Backend 내부의 다음 경로에서 제공됩니다.

```text
/swagger
```

Swagger 원본 명세는 다음 경로에서 확인할 수 있습니다.

```text
/swagger.yaml
```

---

## 데이터베이스 구조

### `users`

사용자 계정 정보를 저장합니다.

| 주요 컬럼      | 설명        |
| ---------- | --------- |
| `id`       | 사용자 고유 ID |
| `username` | 사용자 아이디   |
| `password` | 해시된 비밀번호  |

### `posts`

게시글과 작성자 정보를 저장합니다.

| 주요 컬럼     | 설명             |
| --------- | -------------- |
| `id`      | 게시글 고유 ID      |
| `title`   | 게시글 제목         |
| `content` | 게시글 내용         |
| `writer`  | 작성자 아이디        |
| `user_id` | 작성자 사용자의 고유 ID |

`writer`는 화면에 작성자 이름을 표시하기 위해 사용하고, 실제 수정·삭제 권한은 `user_id`를 기준으로 검증합니다.

### `files`

업로드된 파일의 메타데이터를 저장합니다.

| 주요 컬럼         | 설명               |
| ------------- | ---------------- |
| `id`          | 파일 고유 ID         |
| `filename`    | 사용자가 업로드한 원본 파일명 |
| `saved_name`  | 서버에 저장된 파일명      |
| `file_path`   | 파일 저장 경로         |
| `upload_type` | 정상 또는 취약 업로드 구분  |
| `user_id`     | 파일을 업로드한 사용자 ID  |
| `uploaded_at` | 업로드 시간           |

---

## 취약점 실습 기능

이 프로젝트는 정상적인 보안 처리와 취약한 구현을 비교할 수 있도록 취약점 실습용 라우트를 별도로 제공합니다.

| 취약점                    | 설명                                      |
| ---------------------- | --------------------------------------- |
| SQL Injection          | 사용자 입력값을 SQL 문자열에 직접 포함했을 때 발생하는 취약점    |
| Stored XSS             | 저장된 게시글이나 댓글의 스크립트가 조회 시 실행되는 취약점       |
| Reflected XSS          | 요청 파라미터로 전달한 스크립트가 응답 화면에 그대로 출력되는 취약점  |
| Broken Authentication  | 인증 처리와 로그인 제어가 충분하지 않은 취약점              |
| Rate Limit Missing     | 반복 로그인 요청에 대한 횟수 제한이 없는 취약점             |
| JWT Validation Missing | JWT의 서명 또는 유효성을 올바르게 검증하지 않는 취약점        |
| Directory Traversal    | 조작된 파일 경로를 통해 상위 디렉터리에 접근할 수 있는 취약점     |
| IDOR                   | 사용자 권한을 검사하지 않고 객체 ID만으로 데이터에 접근하는 취약점  |
| File Upload            | 파일명과 확장자 검증이 미흡하여 위험한 파일을 업로드할 수 있는 취약점 |
| Security Headers       | 주요 보안 응답 헤더가 누락된 상태를 점검하기 위한 항목         |

> 취약 라우트는 웹 보안 학습과 스캐너 테스트를 위해 의도적으로 취약하게 구현되었습니다. 외부에 공개되는 운영 서비스에서 사용하면 안 됩니다.

---

## 주요 취약점 시연 방법

| 취약점                    | 시연 방법                                                                                          |
| ---------------------- | ---------------------------------------------------------------------------------------------- |
| SQL Injection          | `/vuln/login`에서 아이디 또는 비밀번호에 `' OR '1'='1`과 같은 Payload를 입력하여 로그인을 시도합니다.                       |
| Stored XSS             | 취약 게시판이나 댓글 기능에 `<script>alert('XSS')</script>`를 저장한 후 페이지를 다시 조회합니다.                          |
| Reflected XSS          | `/vuln/comment?text=<script>alert('XSS')</script>`처럼 스크립트가 포함된 파라미터를 전달합니다.                    |
| Broken Authentication  | `/vuln/broken-auth`에서 로그인을 반복하고 정상 로그인 기능과 인증 처리 차이를 비교합니다.                                    |
| Rate Limit Missing     | `/vuln/rate-limit`에 동일한 로그인 요청을 반복하여 요청 횟수 제한이 없는지 확인합니다.                                      |
| JWT Validation Missing | `/api/token`에서 JWT를 발급받은 후 `/vuln/profile`에 정상 또는 변조된 토큰을 전달합니다.                               |
| Directory Traversal    | `/vuln/download?file=../../../../etc/passwd`처럼 상위 경로가 포함된 파일명을 전달합니다.                          |
| IDOR                   | `/vuln/posts/edit/{post_id}` 또는 `/vuln/posts/delete/{post_id}`를 이용하여 다른 사용자의 게시글 수정·삭제를 시도합니다. |
| File Upload            | 취약 업로드 기능을 이용하여 정상 업로드에서 허용하지 않는 확장자의 파일을 업로드합니다.                                              |

---

## 환경변수

Backend와 MySQL 실행에는 다음 환경변수가 사용됩니다.

| 환경변수                  | 역할                           |
| --------------------- | ---------------------------- |
| `MYSQL_HOST`          | MySQL 서버 주소                  |
| `MYSQL_DATABASE`      | 사용할 데이터베이스 이름                |
| `MYSQL_USER`          | MySQL 사용자 이름                 |
| `MYSQL_PASSWORD`      | MySQL 사용자 비밀번호               |
| `MYSQL_ROOT_PASSWORD` | MySQL root 계정 비밀번호           |
| `SECRET_KEY`          | Flask Session 데이터 서명에 사용하는 키 |
| `JWT_SECRET`          | JWT 생성 및 서명에 사용하는 키          |

프로젝트 루트의 `.env.example` 파일에서 필요한 환경변수와 예시 형식을 확인할 수 있습니다.

```dotenv
MYSQL_DATABASE=security_db
MYSQL_USER=security
MYSQL_PASSWORD=change-me
MYSQL_ROOT_PASSWORD=change-root-password

SECRET_KEY=change-me-to-a-random-secret-key
JWT_SECRET=change-me-to-a-random-jwt-secret
```

`.env.example`은 필요한 환경변수를 안내하기 위한 예시 파일이므로 실제 비밀번호나 운영용 비밀키를 저장하지 않습니다.

실제 비밀값을 별도의 `.env` 파일로 관리하는 경우 `.env`는 Git에 커밋하지 않아야 합니다. 운영 환경에서는 충분히 길고 예측하기 어려운 값을 사용해야 합니다.

---

## 실행 방법

### Docker Compose 실행

프로젝트 루트에서 다음 명령어를 실행합니다.

```bash
docker compose up -d --build
```

컨테이너 상태를 확인합니다.

```bash
docker compose ps
```

Backend 로그를 확인합니다.

```bash
docker compose logs backend
```

정상적으로 실행되면 Backend 로그에 다음 과정이 표시됩니다.

```text
Initializing database...
데이터베이스 초기화 및 테스트 데이터 생성 완료!
Starting Flask application...
```

전체 서비스를 종료할 때는 다음 명령어를 사용합니다.

```bash
docker compose down
```

### 로컬에서 Flask 실행

로컬에서 실행하려면 먼저 MySQL을 실행하고 Backend에 필요한 환경변수를 설정해야 합니다.

그다음 `Backend` 디렉터리에서 다음 명령어를 실행합니다.

```bash
python init_db.py
python app.py
```

팀 프로젝트의 전체 서비스 연동과 시연은 Docker Compose 실행 방식을 권장합니다.

---

## Docker 내부 서비스 연결

Docker Compose로 실행할 경우 서비스 간 통신에는 컨테이너의 서비스명을 사용합니다.

Scanner에서 Backend를 검사할 때 사용하는 Target URL은 다음과 같습니다.

```text
http://backend:5000
```

Swagger 명세를 함께 사용하는 경우 다음 주소를 사용할 수 있습니다.

```text
http://backend:5000/swagger.yaml
```

`localhost`는 각 컨테이너 자기 자신을 의미하므로 Scanner의 Target URL에 `http://localhost:5000`을 입력하면 Backend에 연결되지 않습니다.

---

## 테스트용 계정

`init_db.py`가 실행되면 다음 시연용 계정이 자동으로 등록됩니다.

| 아이디     | 비밀번호       |
| ------- | ---------- |
| `admin` | `12345678` |
| `test1` | `12345678` |
| `user1` | `12345678` |

테스트 게시글도 함께 생성되므로 컨테이너 실행 직후 게시판 기능과 취약점 시연을 진행할 수 있습니다.

> 위 계정은 로컬 실습과 시연을 위한 계정입니다. 실제 운영 환경에서 사용하면 안 됩니다.

---

## 테스트 데이터와 컨테이너 재시작

컨테이너가 시작될 때 `entrypoint.sh`가 `init_db.py`를 실행하여 필요한 테이블과 시연용 데이터를 확인합니다.

* 시연용 계정은 이미 존재하면 중복 생성하지 않습니다.
* 기본 테스트 게시글도 존재 여부를 확인한 후 누락된 게시글만 다시 생성합니다.
* 기존 데이터는 MySQL Docker 볼륨에 저장되므로 일반적인 컨테이너 재시작 후에도 유지됩니다.
* 스캐너가 생성한 SQL Injection·XSS 테스트 게시글도 일반 재시작만으로는 삭제되지 않습니다.
* 기본 게시글이 삭제된 경우에는 다음 Backend 시작 과정에서 다시 생성될 수 있습니다.

Backend 컨테이너만 재시작하려면 다음 명령어를 사용합니다.

```bash
docker compose restart backend
```

재시작 후 초기화 로그를 확인할 수 있습니다.

```bash
docker compose logs backend --tail 20
```

---

## 시연 환경 완전 초기화

스캐너가 생성한 테스트 데이터까지 제거하고 완전히 깨끗한 시연 환경으로 다시 시작하려면 MySQL 데이터가 저장된 Docker 볼륨을 삭제해야 합니다.

```bash
docker compose down -v
docker compose up -d --build
```

> 주의: `docker compose down -v`는 MySQL 볼륨과 현재 저장된 DB 데이터를 모두 삭제합니다. 복구가 필요한 데이터가 없는지 확인한 후, 발표 직전 초기화 또는 개발용 데이터 재설정이 필요한 경우에만 사용해야 합니다.

볼륨을 삭제하고 다시 실행하면 `init_db.py`가 테이블, 테스트 계정, 테스트 게시글을 새로 생성합니다.

---

### 환경변수 설정

Docker Compose 실행 전에 프로젝트 루트에서 `.env.example`을 `.env`로 복사합니다.

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

macOS/Linux:

```bash
cp .env.example .env
```

생성한 `.env`에서 비밀번호와 비밀키를 실행 환경에 맞게 설정한 후 Docker Compose를 실행합니다.

```bash
docker compose up -d --build
```

`.env`에는 실제 데이터베이스 비밀번호와 비밀키가 포함될 수 있으므로 Git에 커밋하지 않습니다. `.env.example`은 필요한 환경변수를 안내하기 위한 예시 파일이며 실제 비밀값을 포함하지 않습니다.

---

## 보안 설계 포인트

* 비밀번호를 평문이 아닌 Werkzeug 해시값으로 저장
* Flask Session과 JWT 서명 키를 환경변수로 관리
* 회원가입 입력값의 길이와 형식 검증
* 정상 로그인에 실패 횟수 제한 적용
* 게시글 수정·삭제 권한을 `user_id`로 검증
* 정상 라우트와 취약점 실습 라우트 분리
* 정상 파일 업로드에 파일명 및 확장자 검증 적용
* 정상/취약 업로드 파일의 저장 경로 분리
* 업로드 파일과 사용자 정보를 DB에서 연결
* Flask Debug 모드 비활성화
* Swagger UI를 이용한 API 문서 및 테스트 환경 제공

---

## EVulnScanner 연동 흐름

1. Docker Compose로 전체 서비스를 실행합니다.
2. 보안 플랫폼 화면에 접속합니다.
3. Target URL에 `http://backend:5000`을 입력합니다.
4. 필요한 경우 Swagger URL로 `http://backend:5000/swagger.yaml`을 사용합니다.
5. Scanner가 Backend의 정상 및 취약 라우트를 검사합니다.
6. 스캔 결과를 JSON 파일로 저장합니다.
7. Report 서비스에서 결과를 HTML 리포트로 출력합니다.
8. Dashboard에서 전체 탐지 결과를 확인합니다.

---

## 참고 및 주의사항

* 이 Backend는 취약점 학습 및 자동 진단 도구 검증을 위한 데모 서비스입니다.
* `/vuln/*` 경로에는 실습을 위한 취약점이 의도적으로 포함되어 있습니다.
* 실제 개인정보나 중요한 파일을 등록하지 마세요.
* 실제 운영 서버나 외부에 공개된 환경에서 실행하지 마세요.
* 발표 전에 전체 파이프라인과 테스트 계정 로그인을 미리 점검하는 것을 권장합니다.
* 깨끗한 시연 데이터가 필요하면 `docker compose down -v`의 데이터 삭제 범위를 확인한 후 초기화하세요.
