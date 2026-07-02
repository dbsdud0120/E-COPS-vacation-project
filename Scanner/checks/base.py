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
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """검사 함수 하나가 발견한 이슈 하나"""
    check_name: str          # 예: "sql_injection"
    url: str                 # 발견된 위치
    parameter: str | None    # 취약 의심 파라미터/입력명 (없으면 None)
    payload: str | None      # 사용한 페이로드
    severity: Severity
    evidence: str            # 판단 근거 (응답 스니펫, 에러 메시지 등)
    description: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


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
