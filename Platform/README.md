# Platform (Orchestrator) Service

> 이 문서는 **`platform/` 디렉토리 전용 README**입니다. 전체 시스템(Scanner, Report, Nginx, MySQL 등)에 대한 소개와 아키텍처는 프로젝트 루트의 `README.md`를 참고하세요.

Platform은 [Security Scanner Platform](../README.md)의 **오케스트레이터(Orchestrator) 서비스**입니다. 사용자로부터 스캔 요청을 받아 Scanner·Report 마이크로서비스를 순차 호출하고, 작업 상태 관리 및 스캔 진행 상황(로그 스트리밍, 진행률)을 실시간으로 사용자에게 제공하는 Flask 애플리케이션입니다.

---

## 🔗 연동 서비스

Platform은 동일 Docker 네트워크 상의 다음 두 마이크로서비스와 HTTP로 통신합니다. (각 서비스의 상세 구현은 해당 디렉토리의 README를 참고)

| 서비스 | 엔드포인트 | 역할 |
|--------|-----------|------|
| **Scanner** | `POST http://scanner:5001/scan` | 대상 URL의 웹 구조 분석 및 취약점 스캔 수행, 결과를 JSON으로 반환 |
| **Report**  | `POST http://report:5002/report` | Scanner 결과와 정책 점검 결과를 바탕으로 HTML/PDF 리포트 및 대시보드 생성 |

전체 서비스 간 관계(Nginx 리버스 프록시, MySQL 등 포함)는 루트 README의 아키텍처 다이어그램을 참고하세요.

---

## ✨ 주요 기능

- **비동기 스캔 실행**: 스캔 요청 시 백그라운드 스레드로 작업을 처리하여 사용자는 즉시 결과 페이지로 이동, 이후 상태를 폴링하며 확인
- **실시간 진행률 표시**: 스캔 로그(`scan.log`)를 스트리밍 방식으로 파싱하여 진행률(%) 및 현재 단계를 실시간 프로그레스 바로 시각화
- **실시간 로그 스트리밍**: `/logs/<job_id>` 엔드포인트를 통해 오프셋 기반으로 신규 로그 라인만 증분 전송
- **다중 리포트 산출물**: 취약점 상세 리포트(HTML/PDF), 종합 대시보드, 보안 정책 점검 리포트 등 목적별 리포트 제공
- **작업 상태 관리**: `job_id`(UUID) 기준으로 각 스캔 작업의 상태(`Ready → Scanning → Generating Report → Completed/Error`)를 메모리에서 추적
- **컨테이너 헬스체크**: `/health` 엔드포인트로 컨테이너 상태 점검 지원

---

## 📁 디렉토리 구조

```
platform/
├── app.py                  # Flask 오케스트레이터 메인 애플리케이션
├── Dockerfile               # Platform 컨테이너 이미지 정의
├── requirements.txt          # Python 의존성 목록
└── templates/
    ├── index.html           # 스캔 요청 메인 페이지
    └── result.html           # 스캔 진행률 및 결과 다운로드 페이지
```

> `results/` 디렉토리는 저장소에 포함된 파일이 아니라, 컨테이너 실행 중 스캔 요청이 들어올 때마다 `RESULTS_DIR`(`/app/results`) 하위에 `job_id`별로 동적으로 생성되는 **런타임 임시 산출물 디렉토리**입니다.
>
> ```
> /app/results/<job_id>/
> ├── scan.log
> ├── report.html
> ├── report.pdf
> ├── dashboard.html
> └── policy_report.html
> ```
>
> 컨테이너 재시작/재배포 시 함께 초기화되므로, 결과물을 영구 보관하려면 볼륨 마운트나 별도 스토리지 연동이 필요합니다.

---

## 🔌 API 엔드포인트

| Method | Path | 설명 |
|--------|------|------|
| `GET`  | `/` | 메인 페이지 (스캔 요청 폼) |
| `POST` | `/scan` | 스캔 작업 생성 (`url` 파라미터 필요) 후 결과 페이지로 리다이렉트 |
| `GET`  | `/result/<job_id>` | 스캔 진행 상황 및 결과 다운로드 페이지 |
| `GET`  | `/status/<job_id>` | 작업 상태 JSON 조회 (폴링용) |
| `GET`  | `/logs/<job_id>?offset=N` | 스캔 로그 증분 조회 (오프셋 기반) |
| `GET`  | `/download/html/<job_id>` | 취약점 상세 리포트(HTML) 다운로드 |
| `GET`  | `/download/pdf/<job_id>` | 취약점 상세 리포트(PDF) 다운로드 |
| `GET`  | `/download/dashboard/<job_id>` | 종합 대시보드(HTML) 다운로드 |
| `GET`  | `/download/policy/<job_id>` | 보안 정책 점검 리포트(HTML) 다운로드 |
| `GET`  | `/health` | 컨테이너 헬스체크 |

---

## 🔄 스캔 처리 흐름

1. 사용자가 메인 페이지(`index.html`)에서 대상 URL을 입력하고 스캔 요청
2. Platform이 고유 `job_id`(UUID)를 발급하고, 백그라운드 스레드에서 `run_scan_job` 실행
3. Scanner 서비스(`:5001/scan`)에 URL과 `job_id`를 전달하여 취약점 스캔 수행 → 상태: `Scanning`
4. 스캔 진행 중 `scan.log`에 `(n/total) 페이지 점검 중` 형식의 로그가 기록되고, 결과 페이지가 이를 파싱해 진행률(%)로 환산해 표시
5. 스캔 완료 후 Report 서비스(`:5002/report`)에 결과 JSON과 정책 점검 경로를 전달하여 리포트 생성 → 상태: `Generating Report`
6. 리포트(취약점 상세 HTML/PDF, 종합 대시보드, 정책 점검 리포트) 생성이 완료되면 상태를 `Completed`로 변경하고 다운로드 링크 활성화
7. 처리 중 예외 발생 시 상태를 `Error`로 전환하고 오류 메시지를 사용자에게 표시

---

## 🚀 실행 방법

Platform은 단독으로도 빌드/실행할 수 있지만, `scanner`·`report` 서비스가 없으면 스캔이 정상 동작하지 않습니다. **전체 스택 실행은 프로젝트 루트의 `docker-compose.yml`을 사용하세요.**

### Platform 컨테이너만 빌드/실행 (디버깅용)

```bash
cd platform/
docker build -t security-scanner-platform .
docker run -p 8080:8080 security-scanner-platform
```

### 전체 스택 실행 (권장)

```bash
# 프로젝트 루트에서
docker compose up --build
```

실행 후 브라우저에서 `http://localhost` (Nginx 경유) 또는 `http://localhost:8080` (Platform 직접 접근)으로 접속합니다. 자세한 전체 스택 구성은 루트 README를 참고하세요.

---

## ⚙️ 환경 요구사항

- Python 3.11 (slim 이미지 기준)
- Flask
- requests
- 동일 Docker 네트워크 상에서 `scanner`, `report` 서비스가 각각 `5001`, `5002` 포트로 접근 가능해야 함

---

## 📌 참고 사항

- 현재 작업 상태(`scan_jobs`)는 인메모리 딕셔너리로 관리되므로 컨테이너 재시작 시 초기화됩니다. 영속성이 필요할 경우 MySQL 등 외부 저장소 연동을 고려해야 합니다.
- 스캔 진행률의 세밀한 갱신은 Scanner가 기록하는 `(n/total) 페이지 점검 중` 로그 포맷에 의존하므로, Scanner 측 로그 포맷 변경 시 `result.html`의 정규식(`scanProgressPattern`)도 함께 갱신이 필요합니다.
- 본 서비스는 진단 목적의 도구이며, **소유하거나 명시적으로 스캔 권한을 부여받은 대상**에 대해서만 사용해야 합니다.
