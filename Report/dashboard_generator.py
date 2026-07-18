# -*- coding: utf-8 -*-
"""
dashboard_generator.py  (3주차: 대시보드 제작)

report_generator_v2.py 가 만드는 "취약점 하나하나의 상세 카드형 리포트" 와 달리,
이 스크립트는 "숫자와 그래프로 전체 현황을 한눈에 보여주는 요약 대시보드"를 만든다.

- 전체/등급별(Critical, High, Medium, Low) 취약점 개수
- 취약점 유형별 개수 (막대그래프)
- 등급별 비율 (도넛차트)
- Critical/High 상위 항목 목록

report_generator_v2.py 와 같은 폴더(Report/)에 두고 실행해야 한다.
(내부의 데이터 정규화 함수들을 그대로 재사용하기 때문)

사용법:
    python3 dashboard_generator.py <scanner_result.json> [출력_prefix] [가이드파일_폴더]

예시:
    python3 dashboard_generator.py latest.json dashboard .
    -> dashboard.html 생성 (브라우저로 열어서 확인)
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from collections import Counter

from jinja2 import Environment

# report_generator_v2.py 에 이미 만들어둔 정규화 로직을 그대로 재사용
from report_generator_v2 import (
    SEVERITY_ORDER,
    SEVERITY_COLOR,
    extract_raw_items,
    get_field,
    normalize_type,
    normalize_severity,
    load_scan_result,
)

jinja_env = Environment(autoescape=True)

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>보안 취약점 대시보드</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<style>
  body {
    font-family: "Noto Sans CJK KR", "Malgun Gothic", sans-serif;
    background: #0F1117;
    color: #E6E6EA;
    margin: 0;
    padding: 32px 40px;
  }
  h1 { font-size: 26px; margin-bottom: 4px; }
  .meta { color: #9AA0AC; font-size: 13px; margin-bottom: 24px; }

  .summary { display: flex; gap: 12px; margin-bottom: 28px; }
  .summary-box {
    flex: 1; background: #171A23; border: 1px solid #262A36;
    border-radius: 10px; padding: 18px; text-align: center;
  }
  .summary-count { font-size: 30px; font-weight: 700; }
  .summary-label { font-size: 12px; color: #9AA0AC; margin-top: 6px; }

  .charts { display: flex; gap: 20px; margin-bottom: 28px; }
  .chart-card {
    flex: 1; background: #171A23; border: 1px solid #262A36;
    border-radius: 10px; padding: 18px;
  }
  .chart-title { font-size: 14px; font-weight: 700; margin-bottom: 12px; color: #9AA0AC; }

  .top-list { background: #171A23; border: 1px solid #262A36; border-radius: 10px; padding: 18px; }
  .top-list h2 { font-size: 16px; margin: 0 0 12px; }
  .top-item {
    display: flex; justify-content: space-between; align-items: center;
    padding: 10px 0; border-bottom: 1px solid #262A36; font-size: 13.5px;
  }
  .top-item:last-child { border-bottom: none; }
  .badge {
    font-size: 11px; font-weight: 700; padding: 2px 10px; border-radius: 999px; color: #14151b;
  }
  .empty { color: #9AA0AC; font-size: 13px; padding: 10px 0; }
</style>
</head>
<body>
  <h1>보안 취약점 대시보드</h1>
  <div class="meta">대상: {{ target }} | 스캔일: {{ scan_date }} | 생성일시: {{ generated_at }} | 총 {{ total }}건</div>

  <div class="summary">
    {% for sev in severity_order %}
    <div class="summary-box">
      <div class="summary-count" style="color: {{ colors[sev] }}">{{ severity_counts[sev] }}</div>
      <div class="summary-label">{{ sev }}</div>
    </div>
    {% endfor %}
  </div>

  <div class="charts">
    <div class="chart-card">
      <div class="chart-title">등급별 비율</div>
      <canvas id="severityChart" height="220"></canvas>
    </div>
    <div class="chart-card">
      <div class="chart-title">취약점 유형별 개수</div>
      <canvas id="typeChart" height="220"></canvas>
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

  <script>
    const severityLabels = {{ severity_labels_json }};
    const severityData = {{ severity_data_json }};
    const severityColors = {{ severity_colors_json }};

    new Chart(document.getElementById('severityChart'), {
      type: 'doughnut',
      data: {
        labels: severityLabels,
        datasets: [{ data: severityData, backgroundColor: severityColors, borderWidth: 0 }]
      },
      options: {
        plugins: { legend: { labels: { color: '#E6E6EA' } } }
      }
    });

    const typeLabels = {{ type_labels_json }};
    const typeData = {{ type_data_json }};

    new Chart(document.getElementById('typeChart'), {
      type: 'bar',
      data: {
        labels: typeLabels,
        datasets: [{ data: typeData, backgroundColor: '#35C2E8', borderRadius: 4 }]
      },
      options: {
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#9AA0AC' }, grid: { color: '#262A36' } },
          y: { ticks: { color: '#E6E6EA' }, grid: { display: false } }
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
            "color": SEVERITY_COLOR.get(v_sev, "#8992A9"),
        })

    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    for v in vulns:
        if v["severity"] in severity_counts:
            severity_counts[v["severity"]] += 1

    type_counts = Counter(v["type"] for v in vulns)
    # 개수 많은 순으로 정렬
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
        target=data.get("target", "-"),
        scan_date=data.get("scan_date", "-"),
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        total=len(dash["vulns"]),
        severity_order=SEVERITY_ORDER,
        severity_counts=dash["severity_counts"],
        colors=SEVERITY_COLOR,
        top_items=dash["top_items"],
        severity_labels_json=json.dumps(SEVERITY_ORDER, ensure_ascii=False),
        severity_data_json=json.dumps([dash["severity_counts"][s] for s in SEVERITY_ORDER]),
        severity_colors_json=json.dumps([SEVERITY_COLOR[s] for s in SEVERITY_ORDER]),
        type_labels_json=json.dumps(dash["type_labels"], ensure_ascii=False),
        type_data_json=json.dumps(dash["type_data"]),
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
