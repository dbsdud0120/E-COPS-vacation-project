"""
checks/base.py
--------------
모든 검사(check) 모듈이 공유하는 공통 인터페이스.

규칙:
  - 각 check 함수는 시그니처를 (session, page: PageInfo, payloads: list[str]) -> list[Finding] 로 통일한다.
  - 이렇게 하면 scanner.py는 check 함수가 SQLi인지 XSS인지 몰라도
    동일한 방식으로 호출/집계할 수 있다.
  - 아직 취약 서버가 없으므로 실제 판별 로직은 "샘플/틀" 수준이며,
    TODO 주석으로 다음 주차에 채울 부분을 표시한다.

⚙️ 3주차: Report(report_generator.py)가 읽는 스키마와 이름을 맞추기 위해
   Finding.to_dict()의 출력 필드/값을 아래처럼 변환한다 (Scanner 내부 로직/각
   checks/*.py에서 쓰는 check_name, Severity enum 값 자체는 그대로 유지하고,
   "출력 시점"에만 변환한다 — 각 check 모듈 코드는 수정할 필요 없음):
     - check_name  -> type      (VULN_TYPE_MAP으로 Report/mitigation_guide.md 표기와 동일한 이름 매핑)
     - severity    -> Capitalize (critical -> Critical 등, SEVERITY_DISPLAY_MAP)
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# check_name(Scanner 내부 값) -> Report/mitigation_guide.md 표기 이름
# ⚠️ Report의 mitigation_guide.md 표와 "정확히" 같은 문자열이어야 대응방안이 매칭됨.
#    Notion "Scanner 담당" 항목에 정의된 매핑을 그대로 반영.
VULN_TYPE_MAP: dict[str, str] = {
    "sql_injection": "SQL Injection",
    "xss": "Reflected XSS",
    "stored_xss": "Stored XSS",
    "file_upload": "File Upload",
    "directory_traversal": "Directory Traversal",
    "broken_authentication": "Broken Authentication",
    "idor": "IDOR",
    "missing_jwt_verification": "Missing JWT Verification",
    "missing_rate_limiting": "Missing Rate Limiting",
    # security_headers는 mitigation_guide.md 표에는 아직 없음 (Report 담당이 행 추가 예정,
    # README "아직 남은 것" 참고). 이름 형식만 나머지와 통일해서 미리 맞춰둠.
    "security_headers": "Security Headers",
}

# Severity(Scanner 내부 값, 소문자) -> Report 표기(Capitalize)
# ⚠️ Report의 SEVERITY_ORDER = ["Critical","High","Medium","Low"] 에는 Info가 없음.
#    (Scanner에는 info가 있지만 Report에는 없다는 점은 Notion에도 "팀에서 결정 필요"로 남아있음.)
#    우선 나머지와 표기 스타일을 맞추기 위해 "Info"로 매핑해두되, Report가 SEVERITY_ORDER/
#    summary 집계에 Info를 추가하기 전까지는 요약 카운트에는 잡히지 않고 카드에만 표시됨.
#    팀 논의 후 값이 확정되면 여기 한 줄만 바꾸면 됨.
SEVERITY_DISPLAY_MAP: dict[str, str] = {
    Severity.CRITICAL.value: "Critical",
    Severity.HIGH.value: "High",
    Severity.MEDIUM.value: "Medium",
    Severity.LOW.value: "Low",
    Severity.INFO.value: "Info",  # TODO(팀 결정 필요): Report의 SEVERITY_ORDER에 Info 추가 여부
}


def _display_type(check_name: str) -> str:
    if check_name in VULN_TYPE_MAP:
        return VULN_TYPE_MAP[check_name]
    # 매핑에 없는 새 check가 추가된 경우를 대비한 방어적 fallback.
    # (mitigation_guide.md에 없는 이름일 수 있으니 경고를 남김 -> VULN_TYPE_MAP에 등록 필요)
    fallback = check_name.replace("_", " ").title()
    print(
        f"[checks.base] 경고: check_name '{check_name}'이 VULN_TYPE_MAP에 없어 "
        f"자동 변환된 이름을 사용합니다 -> '{fallback}' (mitigation_guide.md와 안 맞을 수 있음)"
    )
    return fallback


def _display_severity(severity: Severity) -> str:
    value = severity.value if isinstance(severity, Severity) else str(severity)
    return SEVERITY_DISPLAY_MAP.get(value, value.capitalize())


@dataclass
class Finding:
    """검사 함수 하나가 발견한 이슈 하나"""
    check_name: str          # 예: "sql_injection" (내부용 원본 값)
    url: str                 # 발견된 위치
    parameter: str | None    # 취약 의심 파라미터/입력명 (없으면 None)
    payload: str | None      # 사용한 페이로드
    severity: Severity
    evidence: str            # 판단 근거 (응답 스니펫, 에러 메시지 등)
    description: str

    def to_dict(self) -> dict:
        """
        결과 JSON(Report가 읽는 스키마)으로 직렬화.
        check_name -> type, severity -> Capitalize 로 변환해서 내보낸다.
        (parameter/payload는 디버깅에 유용한 부가 정보라 그대로 유지 — Report 템플릿은
        모르는 필드를 무시하므로 렌더링에 영향 없음)
        """
        return {
            "type": _display_type(self.check_name),
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "severity": _display_severity(self.severity),
            "evidence": self.evidence,
            "description": self.description,
        }


def make_finding(
    check_name: str,
    url: str,
    severity: Severity,
    evidence: str,
    description: str,
    parameter: str | None = None,
    payload: str | None = None,
) -> Finding:
    """Finding 생성 헬퍼 (각 check 모듈에서 반복 코드를 줄이기 위함)"""
    return Finding(
        check_name=check_name,
        url=url,
        parameter=parameter,
        payload=payload,
        severity=severity,
        evidence=evidence,
        description=description,
    )
