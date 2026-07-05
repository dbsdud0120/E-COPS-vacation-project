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
    return parser.parse_args()


def run_scan(target_url: str, depth: int, check_names: list[str]) -> dict:
    print(f"[scanner] 크롤링 시작: {target_url} (depth={depth})")
    crawler = Crawler(target_url, max_depth=depth)
    pages = crawler.crawl()
    print(f"[scanner] 크롤링 완료: 페이지 {len(pages)}개 수집")

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

    result = {
        "target": target_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "pages_crawled": len(pages),
        "checks_run": check_names,
        "findings_count": len(all_findings),
        "findings": [f.to_dict() for f in all_findings],
    }
    return result


def save_result(result: dict) -> str:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{timestamp}.json"
    filepath = os.path.join(RESULTS_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    return filepath


def main():
    args = parse_args()
    check_names = [c.strip() for c in args.checks.split(",") if c.strip()]

    result = run_scan(args.url, args.depth, check_names)
    filepath = save_result(result)

    print(f"[scanner] 스캔 완료. 발견된 이슈: {result['findings_count']}건")
    print(f"[scanner] 결과 저장: {filepath}")


if __name__ == "__main__":
    main()
