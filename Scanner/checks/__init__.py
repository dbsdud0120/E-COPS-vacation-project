"""
checks/__init__.py
-------------------
scanner.py가 "어떤 검사들을 실행할지" 한 곳에서 관리하기 위한 레지스트리.

새 검사를 추가하려면:
  1. checks/새검사이름.py 파일 생성 (run(session, page, payloads) 함수 구현, base.py 참고)
  2. payloads/새검사이름.txt 파일 생성 (payload가 필요 없는 검사면 빈 파일이어도 무방)
  3. 아래 CHECK_REGISTRY에 한 줄 추가
"""

from . import sql_injection
from . import xss
from . import directory_traversal
from . import stored_xss
from . import idor
from . import security_headers

# key: check 이름 (payloads/<key>.txt 파일명과 일치해야 함)
# value: run(session, page, payloads) -> list[Finding] 함수
CHECK_REGISTRY = {
    "sql_injection": sql_injection.run,
    "xss": xss.run,
    "directory_traversal": directory_traversal.run,
    "stored_xss": stored_xss.run,
    "idor": idor.run,
    "security_headers": security_headers.run,
}
