# -*- coding: utf-8 -*-
"""
report_generator.py  (v2 — 저번주 피드백 4가지 전부 반영)

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

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_COLOR = {
    "Critical": "#E5484D",
    "High": "#F59E0B",
    "Medium": "#EAB308",
    "Low": "#10B981",
    "Info": "#94A3B8",
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

# ─────────────────────────────────────────────
# [신규] 비즈니스/컴플라이언스 관점 설명
#   - business_risk   : 기술 지식이 없는 사람도 이해할 수 있는 "회사가 실제로 입는 피해"
#   - compliance_note : 관련 규제/감사 관점에서 왜 문제가 되는지
#   숫자(피해 금액, 유출 인원 등)는 실제 사고 통계가 아니므로 여기서는 넣지 않는다.
#   대신 "어떤 규제가 적용되는지, 그 규제의 처벌 상한 구조가 어떤지"처럼
#   공개적으로 확인 가능한 규정 자체만 안내한다.
# ─────────────────────────────────────────────
BUSINESS_IMPACT_MAP = {
    "SQL Injection": {
        "business_risk": "데이터베이스 전체에 접근당할 수 있어, 고객 개인정보·결제정보가 통째로 유출될 위험이 있습니다. 유출 규모가 클수록 고객 이탈과 브랜드 신뢰도 하락으로 이어집니다.",
        "compliance_note": "개인정보 유출 사고로 분류되어 국내 개인정보보호법(신고 의무·과징금) 또는 해외 이용자가 있다면 GDPR(전 세계 매출의 최대 4% 또는 2천만 유로 중 큰 금액이 상한) 적용 대상이 될 수 있습니다.",
    },
    "Reflected XSS": {
        "business_risk": "공격자가 만든 링크를 사용자가 클릭하는 순간 세션이 탈취되거나 피싱 페이지로 유도될 수 있어, 계정 탈취로 인한 2차 피해와 사용자 신뢰 저하로 이어질 수 있습니다.",
        "compliance_note": "이 취약점을 통해 개인정보가 탈취되면, SQL Injection과 동일하게 개인정보 유출 규제(신고 의무·과징금) 대상이 될 수 있습니다.",
    },
    "Stored XSS": {
        "business_risk": "악성 스크립트가 게시글 등에 영구 저장되어, 접속하는 모든 사용자에게 자동으로 실행됩니다. 한 명이 아니라 다수 사용자 세션이 동시에 탈취될 수 있어 파급 범위가 훨씬 큽니다.",
        "compliance_note": "다수 사용자를 대상으로 한 대규모 사고로 이어질 경우, 감독기관에 대한 신고 의무 및 과징금 리스크가 커집니다.",
    },
    "File Upload": {
        "business_risk": "서버 자체를 장악당할 수 있어(웹쉘 업로드), 시스템 안의 모든 데이터는 물론 같은 네트워크의 다른 시스템까지 위협받고, 서비스 전체가 중단될 수 있습니다.",
        "compliance_note": "시스템 전체 장악은 '중대한 침해사고'로 분류될 가능성이 높아, 과징금과 별개로 안전조치 의무 위반에 따른 책임 소지가 있습니다.",
    },
    "Directory Traversal": {
        "business_risk": "서버 내부의 설정 파일, 소스코드, 인증정보 등이 유출될 수 있고, 이 정보가 다른 공격(예: DB 접속정보 탈취 후 직접 접근)에 재사용될 수 있습니다.",
        "compliance_note": "유출된 파일에 개인정보나 인증정보가 포함되어 있다면, SQL Injection과 동일하게 개인정보 유출 규제 대상이 됩니다.",
    },
    "Broken Authentication": {
        "business_risk": "계정 탈취가 대량으로 발생할 수 있어, 명의 도용이나 부정 결제 같은 사용자 직접 피해로 이어지고, 이는 서비스에 대한 신뢰를 근본적으로 훼손합니다.",
        "compliance_note": "다수 계정이 탈취되면 '안전성 확보조치 미비'로 판단되어, 과징금 산정 시 불리한 가중 요소가 될 수 있습니다.",
    },
    "IDOR": {
        "business_risk": "권한 없는 사용자가 다른 사용자의 개인정보·주문내역 등에 손쉽게 접근할 수 있고, 자동화된 스크립트로 전체 사용자 데이터를 순차적으로 긁어갈 수 있어 피해 규모가 매우 커질 수 있습니다.",
        "compliance_note": "대량 개인정보 접근을 허용하는 구조적 결함으로, 감독기관 조사 시 '기술적 보호조치 미흡'으로 지적될 가능성이 높습니다.",
    },
    "Missing JWT Verification": {
        "business_risk": "인증 시스템 자체가 무력화되어, 공격자가 임의의 사용자(심지어 관리자)로 위장해 시스템 전체에 접근할 수 있습니다. 사실상 인증이 없는 것과 같은 상태입니다.",
        "compliance_note": "인증 우회는 가장 심각한 안전조치 위반 사례 중 하나로 간주되어, 과징금 산정 시 최상위 가중 요소가 될 가능성이 있습니다.",
    },
    "Missing Rate Limiting": {
        "business_risk": "무차별 대입 공격, 대량 계정 탈취 시도, 서비스 거부(DoS) 공격에 취약해져 서비스 가용성이 저하되고, 이는 매출 손실로 직결될 수 있습니다.",
        "compliance_note": "직접적인 개인정보 유출은 아니지만, 이 취약점이 다른 공격(예: Broken Authentication)의 성공률을 높이는 촉매 역할을 합니다.",
    },
    "Security Headers": {
        "business_risk": "단독으로는 치명적이지 않지만, 클릭재킹·XSS 등 다른 공격의 성공 가능성과 피해 범위를 키우는 '기본 방어선 부재' 상태입니다.",
        "compliance_note": "ISMS-P 등 보안 인증 심사의 기본 점검 항목으로, 미비할 경우 인증 심사에 불리하게 작용할 수 있습니다.",
    },
}

DEFAULT_BUSINESS_IMPACT = {
    "business_risk": "이 유형의 취약점에 대한 비즈니스 영향 설명이 아직 정의되지 않았습니다. BUSINESS_IMPACT_MAP에 항목을 추가해주세요.",
    "compliance_note": "-",
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

        impact = BUSINESS_IMPACT_MAP.get(v_type, DEFAULT_BUSINESS_IMPACT)

        v = {
            "type": v_type,
            "url": get_field(raw, "url") or "-",
            "severity": v_sev,
            "evidence": get_field(raw, "evidence") or "-",
            "description": get_field(raw, "description") or "-",
            "color": SEVERITY_COLOR.get(v_sev, "#8992A9"),
            "mitigation": mitigation_map.get(v_type, "대응 방안 미정의 (mitigation_guide.md 확인 필요)"),
            "business_risk": impact["business_risk"],
            "compliance_note": impact["compliance_note"],
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
    background: #F5F6FA;
    color: #1F2430;
    margin: 0;
    padding: 32px 40px;
  }
  h1 { font-size: 24px; margin-bottom: 4px; color: #111827; }
  .meta { color: #6B7280; font-size: 13px; margin-bottom: 20px; }
  .summary { display: flex; gap: 10px; margin-bottom: 24px; flex-wrap: wrap; }
  .summary-box {
    flex: 1; min-width: 80px; background: #FFFFFF; border: 1px solid #E2E5EC;
    border-radius: 8px; padding: 12px; text-align: center;
    box-shadow: 0 1px 2px rgba(0,0,0,0.04);
  }
  .summary-count { font-size: 22px; font-weight: 700; }
  .summary-label { font-size: 11px; color: #6B7280; margin-top: 4px; }
  .card {
    background: #FFFFFF; border: 1px solid #E2E5EC; border-left: 4px solid;
    border-radius: 8px; padding: 14px 18px; margin-bottom: 12px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
  }
  .card-header { display: flex; justify-content: space-between; align-items: center; }
  .vuln-title { font-size: 15px; font-weight: 700; color: #111827; }
  .badge {
    font-size: 11px; font-weight: 700; padding: 2px 10px; border-radius: 999px; color: #FFFFFF;
  }
  .url { font-family: monospace; font-size: 12px; color: #6B7280; margin: 4px 0 10px; }
  .field-label { font-size: 10.5px; text-transform: uppercase; color: #6B7280; margin-top: 8px; }
  .field-value {
    font-size: 12.5px; background: #F9FAFB; border: 1px solid #E2E5EC;
    border-radius: 6px; padding: 6px 8px; margin-top: 3px;
    white-space: pre-wrap; word-break: break-word; color: #1F2430;
  }
  .mitigation { color: #059669; }
  .business-box {
    margin-top: 10px; background: #F8FAFC; border: 1px solid #E2E5EC;
    border-radius: 8px; padding: 10px 12px;
  }
  .business-box .label { font-size: 10.5px; text-transform: uppercase; color: #2563EB; font-weight: 700; margin-bottom: 4px; }
  .business-box .text { font-size: 12.5px; line-height: 1.55; color: #374151; }
  .business-box + .business-box { margin-top: 8px; }
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

    <div class="business-box">
      <div class="label">💼 비즈니스 영향</div>
      <div class="text">{{ v.business_risk }}</div>
    </div>
    <div class="business-box">
      <div class="label">⚖️ 컴플라이언스 관점</div>
      <div class="text">{{ v.compliance_note }}</div>
    </div>
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

    generate(json_arg, prefix_arg, guides_arg)
