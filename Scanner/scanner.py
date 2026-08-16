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

from crawler import Crawler, PageInfo, FormInfo
from checks import CHECK_REGISTRY
from swagger_seed import load_seed_urls, load_post_form_seeds
from auth import login as auth_login

PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "payloads")

# Platform이 job_id별 결과 디렉터리를 넘겨줄 수 있도록 RESULTS_DIR을 환경 변수로 오버라이드 가능하게 함.
# 값이 없으면 기존처럼 Scanner 내부 results/ 디렉터리를 사용 (로컬 실행 시 하위 호환).
DEFAULT_RESULTS_DIR = os.path.join(
    os.path.dirname(__file__),
    "results"
)

RESULTS_DIR = os.environ.get(
    "RESULTS_DIR",
    DEFAULT_RESULTS_DIR
)


def load_payloads(check_name: str) -> list[str]:
    """payloads/<check_name>.txt 를 읽어 줄 단위 리스트로 반환

    빈 줄과 '#'으로 시작하는 주석 줄은 제외한다. (예: file_upload.txt,
    idor.txt, broken_authentication.txt 등은 사용법 설명을 '#' 주석으로
    파일 맨 위에 적어두는데, 이 필터링이 없으면 주석 줄 자체가 payload로
    취급되어 실제 payload가 아닌 문자열로 요청을 보내는 문제가 있었음.)
    """
    path = os.path.join(PAYLOADS_DIR, f"{check_name}.txt")
    if not os.path.exists(path):
        print(f"[scanner] 경고: payload 파일 없음 -> {path} (빈 목록으로 진행)")
        return []
    payloads = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            payloads.append(line)
    return payloads


def parse_args():
    parser = argparse.ArgumentParser(description="웹 자동 진단 Scanner")
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

        # POST 전용 라우트(/vuln/login, /api/token 등)는 GET으로 방문할 방법이 없어서
        # 위 seed_urls(=GET 가능한 경로만)에는 포함되지 않는다. 실제 HTTP 요청 없이,
        # swagger에 문서화된 필드 이름으로 "가상 폼 페이지"를 만들어 pages에 추가한다.
        # 이렇게 해두면 sql_injection.py/xss.py 등 "page.forms의 POST 폼을 테스트하는"
        # 기존 check들이 별도 수정 없이 이 라우트들도 자동으로 테스트하게 된다.
        post_seeds = load_post_form_seeds(swagger_source, target_url)
        for seed in post_seeds:
            form = FormInfo(
                action=seed["url"],
                method="POST",
                inputs=seed["inputs"],
                input_types={name: "text" for name in seed["inputs"]},
            )
            pages.append(PageInfo(
                url=seed["url"],
                status_code=200,  # 실제 요청은 안 보냈으므로 임의값(성공으로 간주)
                forms=[form],
            ))
        if post_seeds:
            print(f"[scanner] swagger 기반 POST 전용 라우트 {len(post_seeds)}개를 가상 폼으로 추가")

    session = requests.Session()

    # 여러 check(특히 stored_xss)가 로그인 상태에서만 도달 가능한 기능(글 작성 등)을
    # 테스트해야 하므로, payloads/broken_authentication.txt에 있는 첫 번째 테스트
    # 계정으로 미리 로그인해서 세션 쿠키를 확보해둔다.
    # 로그인에 실패해도 스캔 자체는 계속 진행한다 (로그인 필요 없는 check는 정상 동작).
    auth_accounts = load_payloads("broken_authentication")
    for line in auth_accounts:
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        auth_username, _, auth_password = line.partition(":")
        logged_in = auth_login(target_url, auth_username.strip(), auth_password.strip())
        if logged_in is not None:
            session = logged_in
            print(f"[scanner] '{auth_username.strip()}' 계정으로 로그인 성공 (로그인 필요한 페이지도 검사에 포함됨)")

            # /api/token은 GET이 없는 POST 전용 라우트라 크롤러/swagger 시드로는
            # 방문할 방법이 없고, jwt_verification.py도 스스로 토큰을 발급받는 로직은
            # 없다(발견한 토큰을 "재사용"하는 로직만 있음). 그래서 여기서 미리 같은
            # 계정으로 토큰을 발급받아, jwt_verification.py가 페이지 간에 토큰을 공유하도록
            # 설계해둔 session._jwt_scan_state에 직접 넣어준다.
            try:
                token_resp = session.post(
                    target_url.rstrip("/") + "/api/token",
                    data={
                        "username": auth_username.strip(),
                        "password": auth_password.strip(),
                    },
                    timeout=5,
                )
                token = token_resp.json().get("token")
            except Exception:
                token = None

            if token:
                state = getattr(session, "_jwt_scan_state", None)
                if state is None:
                    state = {"tokens": set(), "exp_checked": set()}
                    session._jwt_scan_state = state
                state["tokens"].add(token)
                print("[scanner] /api/token에서 JWT 토큰 확보 (JWT 검증 검사에서 재사용됨)")
        else:
            print(f"[scanner] '{auth_username.strip()}' 계정 로그인 실패 - 비로그인 상태로 스캔을 계속합니다")
        break  # 첫 번째 계정만 사용

    # check별 payload는 한 번만 로드해서 재사용
    payloads_by_check = {name: load_payloads(name) for name in check_names}

    all_findings = []

    # total_pages(및 진행률 로그의 분모)는 실제로 검사가 수행되는 페이지 수만 반영해야 한다.
    # status_code == -1(요청 실패/파괴적이라 건너뛴 URL)까지 분모에 포함하면, 그런 페이지가
    # 목록 뒤쪽에 있을 때 마지막으로 출력되는 진행률이 (N-1/N)에서 멈춰 100%에 도달하지 못한다.
    # 그래서 검사 가능한 페이지만 먼저 걸러낸 뒤 그 목록 기준으로 세고 순회한다.
    scannable_pages = [page for page in pages if page.status_code != -1]
    skipped_request_failed = len(pages) - len(scannable_pages)
    total_pages = len(scannable_pages)

    print(f"[scanner] 취약점 점검 시작: 총 {total_pages}개 페이지, {len(check_names)}개 항목 ({', '.join(check_names)})")
    if skipped_request_failed:
        print(f"[scanner] 요청 실패(status_code=-1)로 검사 대상에서 제외된 페이지 {skipped_request_failed}개")

    for page_idx, page in enumerate(scannable_pages, start=1):
        print(f"[scanner] ({page_idx}/{total_pages}) 페이지 점검 중: {page.url}")

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

            if findings:
                print(f"[scanner]   -> [{check_name}] {len(findings)}건 발견")

            all_findings.extend(findings)

    print(f"[scanner] 취약점 점검 완료: 총 {len(all_findings)}건 발견")

    # Report(report_generator.py)가 읽는 스키마에 맞춤
    #   - scanned_at -> scan_date, findings -> vulnerabilities
    #   - 각 항목의 check_name -> type / severity Capitalize 변환은
    #     Finding.to_dict()(checks/base.py)에서 처리됨
    if crawler.skipped_destructive_urls:
        print(
            f"[scanner] 파괴적으로 보여 요청을 보내지 않고 건너뛴 URL {len(crawler.skipped_destructive_urls)}개 "
            "(자동 검사 대상에서 제외됨 - 수동 확인 필요):"
        )
        for skipped_url in crawler.skipped_destructive_urls:
            print(f"[scanner]   - {skipped_url}")

    result = {
        "target": target_url,
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "pages_crawled": len(pages),
        "checks_run": check_names,
        "vulnerabilities_count": len(all_findings),
        "vulnerabilities": [f.to_dict() for f in all_findings],
        # 자동 검사 대상에서 제외된(=요청을 보내지 않은) URL. checks_run에 idor가
        # 없어도 항상 채워지므로, Report 쪽에서 "수동 확인 필요" 목록으로 활용 가능.
        "skipped_destructive_urls": crawler.skipped_destructive_urls,
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

    # run_scan() 중간에도 한 번 로그를 남기지만(크롤링 직후), 그 로그는 스캔이 계속
    # 진행되면서 뒤이은 check 로그에 묻혀 놓치기 쉽다. 스캔이 다 끝난 시점에도 한 번 더
    # 명확히 알려준다 (결과 JSON의 "skipped_destructive_urls" 필드와 동일한 목록).
    skipped = result.get("skipped_destructive_urls") or []
    if skipped:
        print(
            f"[scanner] ⚠ 자동 검사에서 제외된 파괴적 URL {len(skipped)}개 — "
            "수동으로 확인하세요:"
        )
        for skipped_url in skipped:
            print(f"[scanner]   - {skipped_url}")


if __name__ == "__main__":
    main()
