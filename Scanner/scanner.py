"""
scanner.py
----------
전체 파이프라인의 진입점.

흐름:
  URL 입력
    -> crawler.Crawler.crawl()          (같은 도메인 내 페이지/폼 수집)
    -> checks.CHECK_REGISTRY의 각 run() (수집된 페이지마다 검사 실행)
    -> results/<타임스탬프>.json 저장

사용법:
  python scanner.py https://target.example.com
  python scanner.py https://target.example.com --depth 2 --checks sql_injection,xss
  python scanner.py http://localhost:5000 --swagger ../Backend/swagger.yaml
"""

from __future__ import annotations
import argparse
import json
import os
import sys
from datetime import datetime, timezone

import requests

from crawler import Crawler
from checks import CHECK_REGISTRY
from swagger_seed import load_seed_urls

PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "payloads")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")


def load_payloads(check_name: str) -> list[str]:
    """payloads/<check_name>.txt 를 읽어 줄 단위 리스트로 반환"""
    path = os.path.join(PAYLOADS_DIR, f"{check_name}.txt")
    if not os.path.exists(path):
        print(f"[scanner] 경고: payload 파일 없음 -> {path} (빈 목록으로 진행)")
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def parse_args():
    parser = argparse.ArgumentParser(description="웹 자동 진단 Scanner (MVP)")
    parser.add_argument("url", help="검사할 대상 URL (예: https://example.com)")
    parser.add_argument("--depth", type=int, default=2, help="크롤링 최대 깊이 (기본값: 2)")
    parser.add_argument(
        "--checks",
        default=",".join(CHECK_REGISTRY.keys()),
        help="실행할 검사 목록, 콤마로 구분 (기본값: 전체). 예: sql_injection,xss",
    )
    parser.add_argument(
        "--swagger",
        default=None,
        help=(
            "Swagger(OpenAPI) 문서 경로 또는 URL. index.html/posts.html 등에 링크가 없어 "
            "크롤러가 못 찾는 /vuln/* 라우트를 이 문서에서 읽어와 시드로 추가함. "
            "예: ../Backend/swagger.yaml 또는 http://localhost:5000/swagger.json"
        ),
    )
    return parser.parse_args()


def run_scan(target_url: str, depth: int, check_names: list[str], swagger_source: str | None = None) -> dict:
    print(f"[scanner] 크롤링 시작: {target_url} (depth={depth})")
    crawler = Crawler(target_url, max_depth=depth)
    pages = crawler.crawl()
    print(f"[scanner] 크롤링 완료: 페이지 {len(pages)}개 수집")

    if swagger_source:
        seed_urls = load_seed_urls(swagger_source, target_url)
        added = 0
        for url in seed_urls:
            page = crawler.visit_extra(url)
            if page is not None:
                pages.append(page)
                added += 1
        print(f"[scanner] swagger 기반 추가 시드: {len(seed_urls)}개 중 신규 {added}개 추가 (크롤링으로는 못 찾는 라우트 포함)")

    session = requests.Session()

    # check별 payload는 한 번만 로드해서 재사용
    payloads_by_check = {name: load_payloads(name) for name in check_names}

    all_findings = []
    for page in pages:
        if page.status_code == -1:
            continue  # 요청 실패 페이지는 건너뜀

        for check_name in check_names:
            check_fn = CHECK_REGISTRY.get(check_name)
            if check_fn is None:
                print(f"[scanner] 경고: 등록되지 않은 check 이름 '{check_name}' 무시")
                continue

            try:
                findings = check_fn(session, page, payloads_by_check[check_name])
            except Exception as e:
                # 개별 check 실패가 전체 스캔을 중단시키지 않도록 방어
                print(f"[scanner] '{check_name}' 실행 중 오류 ({page.url}): {e}")
                continue

            all_findings.extend(findings)

    # ⚙️ 3주차: Report(report_generator.py)가 읽는 스키마에 맞춤
    #   - scanned_at -> scan_date, findings -> vulnerabilities
    #   - 각 항목의 check_name -> type / severity Capitalize 변환은
    #     Finding.to_dict()(checks/base.py)에서 처리됨
    result = {
        "target": target_url,
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "pages_crawled": len(pages),
        "checks_run": check_names,
        "vulnerabilities_count": len(all_findings),
        "vulnerabilities": [f.to_dict() for f in all_findings],
    }
    return result


def save_result(result: dict) -> str:
    """
    타임스탬프가 붙은 결과 파일(scan_<타임스탬프>.json)을 저장하고,
    동시에 results/latest.json도 같은 내용으로 덮어써서
    Report/통합 담당이 항상 같은 경로(latest.json)에서 최신 결과를 읽을 수 있게 한다.
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{timestamp}.json"
    filepath = os.path.join(RESULTS_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    latest_path = os.path.join(RESULTS_DIR, "latest.json")
    with open(latest_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return filepath


def main():
    args = parse_args()
    check_names = [c.strip() for c in args.checks.split(",") if c.strip()]

    result = run_scan(args.url, args.depth, check_names, swagger_source=args.swagger)
    filepath = save_result(result)

    print(f"[scanner] 스캔 완료. 발견된 이슈: {result['vulnerabilities_count']}건")
    print(f"[scanner] 결과 저장: {filepath}")
    print(f"[scanner] 최신 결과: {os.path.join(RESULTS_DIR, 'latest.json')}")


if __name__ == "__main__":
    main()
