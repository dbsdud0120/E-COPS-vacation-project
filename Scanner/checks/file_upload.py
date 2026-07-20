"""
checks/file_upload.py
-----------------------
파일 업로드 취약점(확장자/파일명 검증 누락) 탐지.
(Notion "Scanner 담당" 6번: file upload 검사 기능 추가)

동작 방식:
  1. 크롤링된 페이지의 <form> 중 파일 입력(input type="file")이 있는 POST 폼을 대상으로 함
     (crawler.py의 FormInfo.input_types로 판별)
  2. payloads/file_upload.txt에 나열된 "위험한" 파일명(.php, .jsp, .phtml, .svg 등)으로
     실제 업로드를 시도
  3. 서버가 확장자/파일명 검증 없이 그대로 수락(응답 200 + 거부 문구 없음)하면 취약으로 판단

⚠️ 실제로 업로드된 파일이 서버에서 실행되는지까지는 확인하지 않음(RCE 트리거는 범위 밖).
   "검증 없이 저장을 수락하는가"까지만 자동 판별하고, 그 이상은 수동 확인이 필요.

⚠️ 안전장치: 업로드하는 파일 내용은 실행 가능한 코드가 아니라 마커 텍스트만 담음
   (실제 웹쉘 코드를 테스트 서버에 심지 않기 위함).

⚙️ Backend/upload.py 기준으로 작성됨 (성공/실패 응답 문구가 다르면 REJECT_HINTS만 수정).
"""
from __future__ import annotations
import uuid

from checks.base import Finding, Severity, make_finding

CHECK_NAME = "file_upload"

DUMMY_VALUE = "test"  # 파일 필드 외 나머지 필수 입력값을 채울 더미 값

# 이 문자열이 응답에 있으면 "거부됨"으로 판단 (Backend/upload.py의 allowed_file() 메시지 기준)
# TODO(Backend 변경 시): 거부 문구가 바뀌면 여기 수정
REJECT_HINTS = ("허용되지 않는", "선택하세요", "존재하지 않")


def _find_file_field(form) -> str | None:
    for name, itype in form.input_types.items():
        if itype == "file":
            return name
    return None


def run(session, page, payloads: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    upload_forms = [f for f in page.forms if f.method == "POST" and _find_file_field(f)]
    if not upload_forms:
        return findings  # 파일 업로드 폼이 없는 페이지

    for form in upload_forms:
        file_field = _find_file_field(form)
        other_fields = [n for n in form.inputs if n != file_field]

        for payload_filename in payloads:
            marker = f"UPLOAD_{uuid.uuid4().hex[:8]}"
            file_content = f"scanner test marker: {marker}".encode("utf-8")

            data = {name: DUMMY_VALUE for name in other_fields}
            files = {file_field: (payload_filename, file_content, "application/octet-stream")}

            try:
                resp = session.post(form.action, data=data, files=files, timeout=5)
            except Exception:
                continue

            rejected = any(hint in resp.text for hint in REJECT_HINTS)
            accepted = resp.status_code == 200 and not rejected

            if accepted:
                findings.append(make_finding(
                    check_name=CHECK_NAME,
                    url=form.action,
                    parameter=file_field,
                    payload=payload_filename,
                    severity=Severity.CRITICAL,
                    evidence=(
                        f"위험한 확장자 파일('{payload_filename}')이 검증 없이 "
                        f"업로드 응답 200(거부 문구 없음)으로 수락됨 (marker={marker})"
                    ),
                    description=(
                        "파일 업로드 기능이 확장자/파일명 검증을 하지 않아, "
                        "실행 가능한 스크립트 파일이 서버에 저장될 수 있습니다."
                    ),
                ))
                break  # 폼당 1건만 기록 (같은 취약점을 여러 payload로 중복 기록 방지)

    return findings
