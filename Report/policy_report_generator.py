# -*- coding: utf-8 -*-
"""
policy_report_generator.py

security_policy_checker.py 가 만든 JSON(policy_result.json)을 읽어서
Pass/Fail/Warning/Manual 배지가 붙은 체크리스트 HTML로 보여준다.

사용법:
    python3 security_policy_checker.py <대상_URL> policy_result.json
    python3 policy_report_generator.py policy_result.json policy_report
    -> policy_report.html 생성
"""

import sys
import json
from pathlib import Path
from jinja2 import Environment

jinja_env = Environment(autoescape=True)

STATUS_COLOR = {
    "Pass": "#5CD3A3",
    "Fail": "#FF4D4F",
    "Warning": "#FFD166",
    "Manual": "#8992A9",
    "Error": "#FF9E42",
}

TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>보안 정책 점검 리포트</title>
<style>
  body {
    font-family: "Noto Sans CJK KR", "Malgun Gothic", sans-serif;
    background: #0F1117; color: #E6E6EA; margin: 0; padding: 32px 40px;
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
    border-radius: 8px; padding: 14px 18px; margin-bottom: 10px;
  }
  .card-header { display: flex; justify-content: space-between; align-items: center; }
  .item-title { font-size: 14.5px; font-weight: 700; }
  .badge { font-size: 11px; font-weight: 700; padding: 2px 10px; border-radius: 999px; color: #14151b; }
  .field-value {
    font-size: 12.5px; background: #0F1117; border: 1px solid #262A36;
    border-radius: 6px; padding: 6px 8px; margin-top: 6px; white-space: pre-wrap;
  }
  .rec { color: #5CD3A3; }
</style>
</head>
<body>
  <h1>보안 정책 점검 리포트</h1>
  <div class="meta">대상: {{ target }} | 점검일시: {{ checked_at }}</div>

  <div class="summary">
    {% for status in status_order %}
    <div class="summary-box">
      <div class="summary-count" style="color: {{ colors[status] }}">{{ summary.get(status, 0) }}</div>
      <div class="summary-label">{{ status }}</div>
    </div>
    {% endfor %}
  </div>

  {% for item in checklist %}
  <div class="card" style="border-left-color: {{ colors.get(item.status, '#8992A9') }};">
    <div class="card-header">
      <div class="item-title">{{ item.name }}</div>
      <div class="badge" style="background: {{ colors.get(item.status, '#8992A9') }};">{{ item.status }}</div>
    </div>
    <div class="field-value">{{ item.detail }}</div>
    {% if item.recommendation and item.recommendation != '-' %}
    <div class="field-value rec">권고: {{ item.recommendation }}</div>
    {% endif %}
  </div>
  {% endfor %}
</body>
</html>
"""

STATUS_ORDER = ["Fail", "Warning", "Manual", "Pass", "Error"]


def generate(json_path_str: str, out_prefix: str = "policy_report"):
    json_path = Path(json_path_str)
    if not json_path.exists():
        print(f"[에러] 입력 파일을 찾을 수 없습니다: {json_path}")
        sys.exit(1)

    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)

    template = jinja_env.from_string(TEMPLATE)
    html_str = template.render(
        target=data.get("target", "-"),
        checked_at=data.get("checked_at", "-"),
        summary=data.get("summary", {}),
        checklist=data.get("checklist", []),
        status_order=STATUS_ORDER,
        colors=STATUS_COLOR,
    )

    out_path = f"{out_prefix}.html"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_str)
    print(f"[완료] 정책 점검 리포트 생성: {out_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("사용법: python3 policy_report_generator.py <policy_result.json> [출력_prefix]")
        sys.exit(1)
    json_arg = sys.argv[1]
    prefix_arg = sys.argv[2] if len(sys.argv) > 2 else "policy_report"
    generate(json_arg, prefix_arg)
