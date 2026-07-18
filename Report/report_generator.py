# -*- coding: utf-8 -*-
"""
report_generator.py  (version 2 저번주 피드백 4가지 전부 반영했습니다)

수정 내역
    [1] 필드명 불일치 해결
        Scanner 실제 출력: {"findings": [{"check_name": "...", "severity": "high", ...}]}
        Report 기존 기대값: {"vulnerabilities": [{"type": "...", "severity": "High", ...}]}
        -> 두 형식을 모두 인식해서 자동으로 표준 형식으로 변환한다.

    [2] 대소문자 불일치 해결 (severity: "high" -> "High")
        -> severity, type 값을 대소문자 관계없이 표준 표기로 정규화한다.

    [3] HTML 자동 이스케이프 적용
        -> Jinja2 Environment를 autoescape=True로 생성.
           evidence/description에 <script> 같은 문자열이 들어와도
           화면엔 문자 그대로("&lt;script&gt;") 표시되고 실제로 실행되지 않는다.

    [4] 샘플 파일 고정 실행 제거
        -> 이제 반드시 실행 시 인자로 JSON 경로를 받아야 하며,
           파일명에 "sample"이 들어가면 경고를 출력해 실수로
           샘플 데이터를 실제 리포트로 착각하지 않도록 한다.

사용법:
    python3 report_generator.py <scanner_result.json> [출력_prefix] [가이드파일_폴더]

예시:
    python3 report_generator.py latest.json final_report .
    -> final_report.html, final_report.pdf 생성
"""

import sys
import re
import json
from pathlib import Path
from datetime import datetime

from jinja2 import Environment
from weasyprint import HTML

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
SEVERITY_COLOR = {
    "Critical": "#FF4D4F",
    "High": "#FF9E42",
    "Medium": "#FFD166",
    "Low": "#5CD3A3",
}

# ─────────────────────────────────────────────
# [1] Scanner의 check_name(snake_case) -> Report 표준 type(Title Case) 매핑
#     mitigation_guide.md 의 표기와 반드시 일치해야 함
# ─────────────────────────────────────────────
TYPE_NORMALIZE_MAP = {
    "sql_injection": "SQL Injection",
    "reflected_xss": "Reflected XSS",
    "stored_xss": "Stored XSS",
    "file_upload": "File Upload",
    "directory_traversal": "Directory Traversal",
    "broken_authentication": "Broken Authentication",
    "idor": "IDOR",
    "authorization": "IDOR",  # Authorization 검사 결과도 IDOR 대응방안과 연결
    "jwt_verification_missing": "Missing JWT Verification",
    "missing_jwt_verification": "Missing JWT Verification",
    "jwt": "Missing JWT Verification",
    "rate_limit_missing": "Missing Rate Limiting",
    "missing_rate_limiting": "Missing Rate Limiting",
    "rate_limit": "Missing Rate Limiting",
    "security_headers": "Security Headers",
    "security_header": "Security Headers",
}

# 이미 Title Case로 들어와도 그대로 통과시키기 위한 정규화(소문자 -> 정식 표기)
TYPE_NORMALIZE_MAP_LOWER_KEYS = {k.lower(): v for k, v in TYPE_NORMALIZE_MAP.items()}
for v in list(TYPE_NORMALIZE_MAP.values()):
    TYPE_NORMALIZE_MAP_LOWER_KEYS.setdefault(v.lower(), v)


def normalize_type(raw_type: str) -> str:
    if not raw_type:
        return "Unknown"
    key = raw_type.strip().lower()
    if key in TYPE_NORMALIZE_MAP_LOWER_KEYS:
        return TYPE_NORMALIZE_MAP_LOWER_KEYS[key]
    # 매핑에 없으면 snake_case -> Title Case로 최선을 다해 변환 (예: "new_check" -> "New Check")
    guess = raw_type.replace("_", " ").strip().title()
    print(f"[경고] '{raw_type}' 은(는) TYPE_NORMALIZE_MAP에 없어 '{guess}' 로 추정 변환했습니다. "
          f"mitigation_guide.md에 새 항목을 추가하고 report_generator.py의 TYPE_NORMALIZE_MAP도 갱신해주세요.")
    return guess


def normalize_severity(raw_sev: str) -> str:
    if not raw_sev:
        return "Low"
    key = raw_sev.strip().lower()
    for s in SEVERITY_ORDER:
        if s.lower() == key:
            return s
    print(f"[경고] 알 수 없는 severity 값 '{raw_sev}' -> 'Low'로 처리합니다.")
    return "Low"


# ─────────────────────────────────────────────
# [1] Scanner 원본 스키마(findings/check_name) <-> Report 표준 스키마(vulnerabilities/type) 모두 지원
# ─────────────────────────────────────────────
def extract_raw_items(data: dict) -> list:
    if "vulnerabilities" in data:
        return data["vulnerabilities"]
    if "findings" in data:
        return data["findings"]
    raise ValueError(
        "JSON에 'vulnerabilities' 또는 'findings' 키가 없습니다. "
        "Scanner 출력 형식이 바뀌었다면 report_generator.py의 extract_raw_items()를 확인해주세요."
    )


FIELD_ALIASES = {
    "type": ["type", "check_name", "checkName", "vuln_type"],
    "url": ["url", "path", "endpoint", "target_url"],
    "severity": ["severity", "risk", "level"],
    "evidence": ["evidence", "proof", "detail"],
    "description": ["description", "message", "desc"],
}


def get_field(item: dict, field: str) -> str:
    for alias in FIELD_ALIASES[field]:
        if alias in item and item[alias]:
            return item[alias]
    return ""


def parse_markdown_table(md_path: Path) -> dict:
    """'|키|값|' 형식의 2열 마크다운 표를 { 키: 값 } 딕셔너리로 변환."""
    if not md_path.exists():
        print(f"[경고] {md_path} 파일을 찾을 수 없어 대응 방안/기준을 채우지 못합니다.")
        return {}

    result = {}
    with open(md_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("|"):
                continue
            cols = [c.strip() for c in line.strip("|").split("|")]
            if len(cols) != 2:
                continue
            key, value = cols
            if re.fullmatch(r"-+", key):
                continue
            if key.startswith("**") and key.endswith("**"):
                continue
            result[key] = value
    return result


def load_scan_result(json_path: Path) -> dict:
    # [4] 샘플 파일을 실수로 실제 리포트에 쓰는 것을 방지하는 경고
    if "sample" in json_path.name.lower():
        print(f"[주의] '{json_path.name}' 은 샘플/테스트 데이터로 보입니다. "
              f"실제 제출용 리포트라면 Scanner가 만든 진짜 결과 파일을 넣어주세요.")

    with open(json_path, encoding="utf-8") as f:
        return json.load(f)


def enrich_vulnerabilities(data: dict, mitigation_map: dict) -> list:
    raw_items = extract_raw_items(data)
    enriched = []

    for raw in raw_items:
        v_type = normalize_type(get_field(raw, "type"))
        v_sev = normalize_severity(get_field(raw, "severity"))

        v = {
            "type": v_type,
            "url": get_field(raw, "url") or "-",
            "severity": v_sev,
            "evidence": get_field(raw, "evidence") or "-",
            "description": get_field(raw, "description") or "-",
            "color": SEVERITY_COLOR.get(v_sev, "#8992A9"),
            "mitigation": mitigation_map.get(v_type, "대응 방안 미정의 (mitigation_guide.md 확인 필요)"),
        }
        enriched.append(v)

    def sort_key(v):
        return SEVERITY_ORDER.index(v["severity"]) if v["severity"] in SEVERITY_ORDER else len(SEVERITY_ORDER)

    return sorted(enriched, key=sort_key)


def build_summary(vulns: list) -> dict:
    summary = {s: 0 for s in SEVERITY_ORDER}
    for v in vulns:
        if v["severity"] in summary:
            summary[v["severity"]] += 1
    return summary


# ─────────────────────────────────────────────
# [3] autoescape=True 인 Jinja2 Environment 사용
#     -> {{ v.description }} 등에 <script> 가 들어와도 자동으로 이스케이프됨
# ─────────────────────────────────────────────
jinja_env = Environment(autoescape=True)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>보안 취약점 스캔 리포트</title>
<style>
  body {
    font-family: "Noto Sans CJK KR", "Malgun Gothic", sans-serif;
    background: #0F1117;
    color: #E6E6EA;
    margin: 0;
    padding: 32px 40px;
  }
  h1 { font-size: 24px; margin-bottom: 4px; }
  .meta { color: #9AA0AC; font-size: 13px; margin-bottom: 20px; }
  .summary { display: flex; gap: 10px; margin-bottom: 24px; }
  .summary-box {
    flex: 1; background: #171A23; border: 1px solid #262A36;
    border-radius: 8px; padding: 12px; text-align: center;
  }
  .summary-count { font-size: 22px; font-weight: 700; }
  .summary-label { font-size: 11px; color: #9AA0AC; margin-top: 4px; }
  .card {
    background: #171A23; border: 1px solid #262A36; border-left: 4px solid;
    border-radius: 8px; padding: 14px 18px; margin-bottom: 12px;
  }
  .card-header { display: flex; justify-content: space-between; align-items: center; }
  .vuln-title { font-size: 15px; font-weight: 700; }
  .badge {
    font-size: 11px; font-weight: 700; padding: 2px 10px; border-radius: 999px; color: #14151b;
  }
  .url { font-family: monospace; font-size: 12px; color: #9AA0AC; margin: 4px 0 10px; }
  .field-label { font-size: 10.5px; text-transform: uppercase; color: #9AA0AC; margin-top: 8px; }
  .field-value {
    font-size: 12.5px; background: #0F1117; border: 1px solid #262A36;
    border-radius: 6px; padding: 6px 8px; margin-top: 3px;
    white-space: pre-wrap; word-break: break-word;
  }
  .mitigation { color: #5CD3A3; }
</style>
</head>
<body>
  <h1>보안 취약점 스캔 리포트</h1>
  <div class="meta">대상: {{ target }} | 스캔일: {{ scan_date }} | 생성일시: {{ generated_at }} | 총 {{ total }}건</div>

  <div class="summary">
    {% for sev in severity_order %}
    <div class="summary-box">
      <div class="summary-count" style="color: {{ colors[sev] }}">{{ summary[sev] }}</div>
      <div class="summary-label">{{ sev }}</div>
    </div>
    {% endfor %}
  </div>

  {% for v in vulns %}
  <div class="card" style="border-left-color: {{ v.color }};">
    <div class="card-header">
      <div class="vuln-title">{{ v.type }}</div>
      <div class="badge" style="background: {{ v.color }};">{{ v.severity }}</div>
    </div>
    <div class="url">{{ v.url }}</div>
    <div class="field-label">설명</div>
    <div class="field-value">{{ v.description }}</div>
    <div class="field-label">증거 (Evidence)</div>
    <div class="field-value">{{ v.evidence }}</div>
    <div class="field-label">대응 방안</div>
    <div class="field-value mitigation">{{ v.mitigation }}</div>
  </div>
  {% endfor %}
</body>
</html>
"""


def generate(json_path_str: str, out_prefix: str = "report", guides_dir: str = "."):
    json_path = Path(json_path_str)
    guides_dir_path = Path(guides_dir)

    if not json_path.exists():
        print(f"[에러] 입력 파일을 찾을 수 없습니다: {json_path}")
        sys.exit(1)

    data = load_scan_result(json_path)
    mitigation_map = parse_markdown_table(guides_dir_path / "mitigation_guide.md")

    vulns = enrich_vulnerabilities(data, mitigation_map)
    summary = build_summary(vulns)

    template = jinja_env.from_string(HTML_TEMPLATE)
    html_str = template.render(
        target=data.get("target", "-"),
        scan_date=data.get("scan_date", "-"),
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        total=len(vulns),
        vulns=vulns,
        summary=summary,
        severity_order=SEVERITY_ORDER,
        colors=SEVERITY_COLOR,
    )

    html_path = f"{out_prefix}.html"
    pdf_path = f"{out_prefix}.pdf"

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_str)
    print(f"[완료] HTML 리포트 생성: {html_path}")

    HTML(string=html_str, base_url=".").write_pdf(pdf_path)
    print(f"[완료] PDF 리포트 생성: {pdf_path}")


if __name__ == "__main__":
    # [4] 인자 없이 실행하면 즉시 안내 후 종료 (샘플 파일 자동 실행 금지)
    if len(sys.argv) < 2:
        print("사용법: python3 report_generator.py <scanner_result.json> [출력_prefix] [가이드파일_폴더]")
        print("주의: 실제 제출용 리포트에는 Scanner가 실행되어 만든 진짜 결과 파일 경로를 넣어주세요.")
        sys.exit(1)

    json_arg = sys.argv[1]
    prefix_arg = sys.argv[2] if len(sys.argv) > 2 else "report"
    guides_arg = sys.argv[3] if len(sys.argv) > 3 else "."
    generate(json_arg, prefix_arg, guides_arg)
    generate(json_arg, prefix_arg, guides_arg) generate(json_arg, prefix_arg, guides_arg)
