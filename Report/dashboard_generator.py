# -*- coding: utf-8 -*-
"""
dashboard_generator.py

Scanner 결과 JSON을 읽어 등급별/유형별 요약 대시보드(HTML, Chart.js)를 생성한다.
Chart.js는 assets/chart.umd.js로 인라인 내장되어 외부 CDN 없이 항상 렌더링된다.
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from collections import Counter

from jinja2 import Environment

from report_generator import (
    SEVERITY_ORDER,
    SEVERITY_COLOR,
    TEAM_NAME,
    TEAM_MEMBERS,
    LOGO_BASE64,
    extract_raw_items,
    get_field,
    normalize_type,
    normalize_severity,
    load_scan_result,
)

jinja_env = Environment(autoescape=True)


def _safe_json(obj):
    """
    JSON을 <script> 태그 안에 리터럴로 직접 삽입할 때 쓰는 헬퍼.
    - Jinja autoescape가 "를 &#34;로 바꾸면 <script> 안에서는 HTML 엔티티가
      디코딩되지 않아 문법이 깨지므로, 템플릿에서 |safe로 이스케이프를
      건너뛰기 위해 여기서 안전한 문자열을 미리 만든다.
    - 데이터에 "</script>"가 섞여 있으면 스크립트 태그가 조기 종료되어
      뒤 내용이 실행 가능한 스크립트로 해석될 수 있어 "</"를 "<\\/"로 이스케이프한다.
    주의: v.type, v.url처럼 HTML 본문에 텍스트로 들어가는 값에는 절대
    |safe를 붙이지 말 것 (Jinja 기본 autoescape를 유지해야 XSS 방지가 됨).
    """
    return json.dumps(obj, ensure_ascii=False).replace("</", "<\\/")


_CHARTJS_PATH = Path(__file__).parent / "assets" / "chart.umd.js"
CHARTJS_INLINE = _CHARTJS_PATH.read_text(encoding="utf-8") if _CHARTJS_PATH.exists() else ""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>보안 취약점 대시보드</title>
<style>
  body {
    font-family: "Noto Sans CJK KR", "Malgun Gothic", sans-serif;
    background: #F5F6FA;
    color: #1F2430;
    margin: 0;
    padding: 32px 40px;
  }
  .header-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
  h1 { font-size: 22px; margin: 0; color: #111827; }
  .brand { display: flex; align-items: center; gap: 10px; }
  .brand-logo { height: 34px; width: auto; display: block; }
  .brand-members { font-size: 11.5px; color: #6B7280; line-height: 1.4; text-align: right; }

  .toolbar {
    display: flex; gap: 22px; font-size: 12.5px; color: #6B7280;
    padding: 10px 0; border-bottom: 1px solid #E2E5EC; margin-bottom: 18px;
  }
  .toolbar b { color: #374151; }

  .section-tab {
    display: inline-flex; align-items: center;
    font-size: 12.5px; font-weight: 700; color: #111827;
    background: #EFF3FF; border: 1px solid #DCE4FA;
    border-bottom: 2px solid #2563EB;
    border-radius: 6px 6px 0 0;
    padding: 6px 14px;
  }

  .stats-row {
    display: flex; border: 1px solid #E2E5EC; border-radius: 0 8px 8px 8px;
    background: #FFFFFF; overflow: hidden; margin-bottom: 24px;
  }
  .stat-item { flex: 1; min-width: 70px; padding: 14px 16px; border-left: 1px solid #E2E5EC; }
  .stat-item:first-child { border-left: none; }
  .stat-label { font-size: 12px; font-weight: 700; color: #111827; margin-bottom: 6px; }
  .stat-value { font-size: 26px; font-weight: 700; line-height: 1; }
  .stat-bar { height: 4px; border-radius: 2px; margin-top: 10px; }

  .charts { display: flex; gap: 16px; margin-bottom: 24px; }
  .chart-card {
    flex: 1; background: #FFFFFF; border: 1px solid #E2E5EC; border-radius: 8px; padding: 18px;
  }
  .chart-title { font-size: 13px; font-weight: 700; color: #111827; margin-bottom: 14px; }
  .chart-canvas-wrap { position: relative; height: 240px; width: 100%; }

  .top-list { background: #FFFFFF; border: 1px solid #E2E5EC; border-radius: 8px; padding: 18px; }
  .top-list h2 { font-size: 14px; font-weight: 700; margin: 0 0 12px; color: #111827; }
  .top-item {
    display: flex; justify-content: space-between; align-items: center;
    padding: 10px 0; border-top: 1px solid #F1F2F6; font-size: 13px; color: #374151;
  }
  .top-item:first-of-type { border-top: none; }
  .badge { font-size: 11px; font-weight: 700; padding: 2px 10px; border-radius: 999px; color: #111827; }
  .empty { color: #9CA3AF; font-size: 13px; padding: 10px 0; }

  .report-footer {
    margin-top: 24px; padding-top: 12px; border-top: 1px solid #E2E5EC;
    font-size: 11.5px; color: #9CA3AF; text-align: center;
  }
</style>
<script>
{{ chartjs_inline | safe }}
</script>
</head>
<body>

  <div class="header-row">
    <h1>보안 취약점 대시보드</h1>
    <div class="brand">
      {% if logo_base64 %}
      <img class="brand-logo" src="data:image/png;base64,{{ logo_base64 }}" alt="{{ team_name }} logo">
      {% endif %}
      <div class="brand-members">{{ team_members }}</div>
    </div>
  </div>

  <div class="toolbar">
    <span><b>대상</b> {{ target }}</span>
    <span><b>스캔일</b> {{ scan_date }}</span>
    <span><b>생성일시</b> {{ generated_at }}</span>
    <span><b>총 건수</b> {{ total }}건</span>
  </div>

  <div class="section-tab">Summary</div>
  <div class="stats-row">
    {% for sev in severity_order %}
    <div class="stat-item">
      <div class="stat-label">{{ sev }}</div>
      <div class="stat-value" style="color: {{ colors[sev] }}">{{ severity_counts[sev] }}</div>
      <div class="stat-bar" style="background: {{ colors[sev] }}"></div>
    </div>
    {% endfor %}
  </div>

  <div class="charts">
    <div class="chart-card">
      <div class="chart-title">등급별 비율</div>
      <div class="chart-canvas-wrap"><canvas id="severityChart"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">취약점 유형별 개수</div>
      <div class="chart-canvas-wrap"><canvas id="typeChart"></canvas></div>
    </div>
  </div>

  <div class="top-list">
    <h2>Critical / High 상위 항목</h2>
    {% for v in top_items %}
    <div class="top-item">
      <span>{{ v.type }} &nbsp;·&nbsp; {{ v.url }}</span>
      <span class="badge" style="background: {{ v.color }};">{{ v.severity }}</span>
    </div>
    {% else %}
    <div class="empty">Critical / High 등급 항목이 없습니다.</div>
    {% endfor %}
  </div>

  <div class="report-footer">
    {{ team_name }} &nbsp;·&nbsp; {{ team_members }}
  </div>

  <script>
    const severityLabels = {{ severity_labels_json | safe }};
    const severityData = {{ severity_data_json | safe }};
    const severityColors = {{ severity_colors_json | safe }};

    new Chart(document.getElementById('severityChart'), {
      type: 'doughnut',
      data: {
        labels: severityLabels,
        datasets: [{ data: severityData, backgroundColor: severityColors, borderWidth: 0 }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#374151' } } }
      }
    });

    const typeLabels = {{ type_labels_json | safe }};
    const typeData = {{ type_data_json | safe }};

    new Chart(document.getElementById('typeChart'), {
      type: 'bar',
      data: {
        labels: typeLabels,
        datasets: [{ data: typeData, backgroundColor: '#2563EB', borderRadius: 4 }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#6B7280' }, grid: { color: '#F1F2F6' } },
          y: { ticks: { color: '#374151' }, grid: { display: false } }
        }
      }
    });
  </script>
</body>
</html>
"""


def build_dashboard_data(data: dict) -> dict:
    raw_items = extract_raw_items(data)

    vulns = []
    for raw in raw_items:
        v_type = normalize_type(get_field(raw, "type"))
        v_sev = normalize_severity(get_field(raw, "severity"))
        vulns.append({
            "type": v_type,
            "url": get_field(raw, "url") or "-",
            "severity": v_sev,
            "color": SEVERITY_COLOR.get(v_sev, "#94A3B8"),
        })

    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    for v in vulns:
        if v["severity"] in severity_counts:
            severity_counts[v["severity"]] += 1

    type_counts = Counter(v["type"] for v in vulns)
    type_items = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)

    top_items = [v for v in vulns if v["severity"] in ("Critical", "High")]
    top_items.sort(key=lambda v: SEVERITY_ORDER.index(v["severity"]))

    return {
        "vulns": vulns,
        "severity_counts": severity_counts,
        "type_labels": [t for t, _ in type_items],
        "type_data": [c for _, c in type_items],
        "top_items": top_items,
    }


def generate(json_path_str: str, out_prefix: str = "dashboard", guides_dir: str = "."):
    json_path = Path(json_path_str)
    if not json_path.exists():
        print(f"[에러] 입력 파일을 찾을 수 없습니다: {json_path}")
        sys.exit(1)

    data = load_scan_result(json_path)
    dash = build_dashboard_data(data)

    template = jinja_env.from_string(DASHBOARD_TEMPLATE)
    html_str = template.render(
        team_name=TEAM_NAME,
        team_members=" · ".join(TEAM_MEMBERS),
        logo_base64=LOGO_BASE64,
        chartjs_inline=CHARTJS_INLINE,
        target=data.get("target", "-"),
        scan_date=data.get("scan_date", "-"),
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        total=len(dash["vulns"]),
        severity_order=SEVERITY_ORDER,
        severity_counts=dash["severity_counts"],
        colors=SEVERITY_COLOR,
        top_items=dash["top_items"],
        severity_labels_json=_safe_json(SEVERITY_ORDER),
        severity_data_json=_safe_json([dash["severity_counts"][s] for s in SEVERITY_ORDER]),
        severity_colors_json=_safe_json([SEVERITY_COLOR[s] for s in SEVERITY_ORDER]),
        type_labels_json=_safe_json(dash["type_labels"]),
        type_data_json=_safe_json(dash["type_data"]),
    )

    out_path = f"{out_prefix}.html"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_str)
    print(f"[완료] 대시보드 생성: {out_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("사용법: python3 dashboard_generator.py <scanner_result.json> [출력_prefix] [가이드파일_폴더]")
        sys.exit(1)

    json_arg = sys.argv[1]
    prefix_arg = sys.argv[2] if len(sys.argv) > 2 else "dashboard"
    guides_arg = sys.argv[3] if len(sys.argv) > 3 else "."

    generate(json_arg, prefix_arg, guides_arg)
