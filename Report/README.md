# Report 모듈

Scanner가 생성한 JSON 스캔 결과를 HTML/PDF 취약점 리포트로 변환하는 기능입니다.

## 폴더 구조
Report/
├── report_generator.py     # 리포트 생성 메인 스크립트
├── mitigation_guide.md      # 취약점 유형별 대응 방안 표
├── severity_guide.md        # 심각도 등급(Critical/High/Medium/Low) 기준
├── sample_result.json       # 테스트용 샘플 스캔 결과
├── sample_report.html       # 샘플 실행 결과 (HTML)
├── sample_report.pdf        # 샘플 실행 결과 (PDF)
└── Dockerfile

## 실행 방법

### 로컬 실행
```bash
pip install Jinja2 WeasyPrint
python3 report_generator.py sample_result.json sample_report
```
→ `sample_report.html`, `sample_report.pdf`가 생성됩니다.

**인자 설명**
- 1번째 인자 (필수): Scanner가 생성한 JSON 결과 파일 경로
- 2번째 인자 (선택, 기본값 `report`): 출력 파일 이름 prefix
- 3번째 인자 (선택, 기본값 `.`): `mitigation_guide.md`, `severity_guide.md`가 위치한 폴더 경로

### Docker 실행
```bash
docker build -t report .
docker run report
```

## 입력 JSON 형식
```json
{
  "target": "스캔 대상 URL",
  "scan_date": "YYYY-MM-DD",
  "vulnerabilities": [
    {
      "type": "취약점 유형",
      "url": "발견 위치",
      "severity": "Critical | High | Medium | Low",
      "evidence": "증거",
      "description": "설명"
    }
  ]
}
```

## 대응 방안 매핑
`mitigation_guide.md`는 `|취약점 유형|대응 방안|` 형식의 마크다운 표로 작성되어 있으며, JSON의 `type` 값과 매칭되어 리포트에 자동으로 삽입됩니다. 매칭되는 유형이 없으면 "대응 방안 미정의"로 표시됩니다.

## 출력
- HTML 리포트: 다크 테마, 심각도별 색상 배지, 요약 카운트 포함
- PDF 리포트: 동일한 내용을 WeasyPrint로 PDF 변환

## 출력
- HTML 리포트: 다크 테마, 심각도별 색상 배지, 요약 카운트 포함
- PDF 리포트: 동일한 내용을 WeasyPrint로 PDF 변환
