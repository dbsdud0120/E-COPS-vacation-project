|**취약점 유형**|**대응 방안**|
|-|-|
|SQL Injection|Prepared Statement(파라미터바인딩) 사용, ORM 사용 권장|
|Reflected XSS|출력 시 HTML Output Encoding 적용|
|Stored XSS|입력값 검증 + 출력 인코딩 + CSP(Content Security Policy) 적용|
|File Upload|확장자 화이트리스트 검증, 업로드 파일 실행 권한 제거, 별도 스토리지 분리|
|Directory Traversal|경로 입력값 검증, 파일 접근을 화이트리스트 기반으로 제한|
|Broken Authentication|로그인 시도 횟수 제한, 세션 토큰 무작위성 강화, MFA 도입|
|IDOR|요청자 권한과 객체 소유자 일치 여부 서버단에서 검증|
|Missing JWT Verification|서명 검증 필수화, 토큰 만료시간 설정, Secret Key 안전하게 관리|
|Missing Rate Limiting|API Gateway 또는 미들웨어 레벨에서 요청 횟수 제한 적용|
