# -*- coding: utf-8 -*-
"""
report_generator.py

사용법:
    python3 report_generator.py <scan_result.json> [출력파일_이름_prefix]

예시:
    python3 report_generator.py sample_result.json report
    -> report.html, report.pdf 생성

이 스크립트가 하는 일:
    1. Scanner가 만든 JSON 결과 파일을 읽는다.
    2. severity_guide.md, mitigation_guide.md 를 읽어서
       각 취약점(type)에 맞는 "대응 방안"을 자동으로 매칭한다.
    3. Jinja2 템플릿으로 HTML 리포트를 만든다.
    4. WeasyPrint로 그 HTML을 PDF로 변환한다.

전제 조건:
    - JSON의 각 항목은 type, url, severity, evidence, description 필드를 가진다.
    - mitigation_guide.md 는 "|취약점 유형|대응 방안|" 형식의 마크다운 표다.
    - severity_guide.md 는 "|등급|기준|" 형식의 마크다운 표다.
    - 이 스크립트와 같은 폴더(또는 --guides 옵션으로 지정한 폴더)에
      severity_guide.md, mitigation_guide.md 가 있어야 한다.
"""

import sys
import json
import re
import os
from pathlib import Path
from datetime import datetime

from jinja2 import Template
from weasyprint import HTML

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
SEVERITY_COLOR = {
    "Critical": "#FF4D4F",
    "High": "#FF9E42",
    "Medium": "#FFD166",
    "Low": "#5CD3A3",
}


def parse_markdown_table(md_path: Path) -> dict:
    """
    '|키|값|' 형식의 2열 마크다운 표를 { 키: 값 } 딕셔너리로 변환.
    헤더 행(**볼드**로 감싸진 행)과 구분선(|-|-|)은 건너뛴다.
    """
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
            # 구분선(|-|-|) 스킵
            if re.fullmatch(r"-+", key):
                continue
            # 헤더 행(**취약점 유형**) 스킵
            if key.startswith("**") and key.endswith("**"):
                continue
            result[key] = value
    return result


def load_scan_result(json_path: Path) -> dict:
    with open(json_path, encoding="utf-8") as f:
        return json.load(f)


def enrich_vulnerabilities(data: dict, mitigation_map: dict) -> list:
    """각 취약점 항목에 대응 방안(mitigation)을 붙이고, 심각도 순으로 정렬."""
    vulns = data.get("vulnerabilities", [])
    for v in vulns:
        v["mitigation"] = mitigation_map.get(v.get("type", ""), "대응 방안 미정의 (mitigation_guide.md 확인 필요)")
        v["color"] = SEVERITY_COLOR.get(v.get("severity", ""), "#8992A9")

    def sort_key(v):
        sev = v.get("severity", "")
        return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)

    return sorted(vulns, key=sort_key)


def build_summary(vulns: list) -> dict:
    summary = {s: 0 for s in SEVERITY_ORDER}
    for v in vulns:
        if v.get("severity") in summary:
            summary[v["severity"]] += 1
    return summary


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


def generate(json_path: str, out_prefix: str = "report", guides_dir: str = "."):
    json_path = Path(json_path)
    guides_dir = Path(guides_dir)

    data = load_scan_result(json_path)
    mitigation_map = parse_markdown_table(guides_dir / "mitigation_guide.md")
    # severity_guide.md 는 등급 기준 설명이라 현재 템플릿에선 직접 쓰진 않지만,
    # 필요하면 여기서 parse_markdown_table(guides_dir / "severity_guide.md") 로 불러와
    # 등급별 툴팁 등에 활용할 수 있다.

    vulns = enrich_vulnerabilities(data, mitigation_map)
    summary = build_summary(vulns)

    html_str = Template(HTML_TEMPLATE).render(
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
    if len(sys.argv) < 2:
        print("사용법: python3 report_generator.py <scan_result.json> [출력_prefix] [가이드파일_폴더]")
        sys.exit(1)

    json_arg = sys.argv[1]
    prefix_arg = sys.argv[2] if len(sys.argv) > 2 else "report"
    guides_arg = sys.argv[3] if len(sys.argv) > 3 else "."

    generate(json_arg, prefix_arg, guides_arg)
