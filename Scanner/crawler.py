"""
crawler.py
----------
대상 URL에서 시작해 같은 도메인 내부의 링크와 form을 수집한다.
결과물은 scanner.py가 각 checks/*.py 함수에 넘겨줄 "타겟 목록"이다.

MVP 범위:
  - GET 요청만 사용 (인증/세션 처리는 다음 주차)
  - depth(탐색 깊이)로 무한 크롤링 방지
  - <a href>, <form> 두 가지만 수집 (JS로 렌더링되는 링크는 다음 주차: Selenium/Playwright 고려)
"""

from __future__ import annotations
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

DEFAULT_HEADERS = {
    "User-Agent": "MiniScanner/0.1 (+internal-security-testing)"
}


@dataclass
class FormInfo:
    """페이지에서 발견한 <form> 하나의 정보"""
    action: str          # 제출 대상 URL (절대경로로 정규화됨)
    method: str          # GET / POST
    inputs: list[str] = field(default_factory=list)  # input name 목록


@dataclass
class PageInfo:
    """크롤링으로 수집한 페이지 하나의 정보"""
    url: str
    status_code: int
    forms: list[FormInfo] = field(default_factory=list)
    # 쿼리스트링 있는 링크는 파라미터 기반 취약점 점검 대상이 되므로 별도 보관
    query_params: list[str] = field(default_factory=list)


class Crawler:
    def __init__(self, base_url: str, max_depth: int = 2, timeout: int = 5, delay: float = 0.2):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.timeout = timeout
        self.delay = delay  # 서버 부담을 줄이기 위한 요청 간 딜레이(초)
        self.visited: set[str] = set()
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def _is_same_domain(self, url: str) -> bool:
        return urlparse(url).netloc == self.domain

    def _normalize(self, base: str, link: str) -> str | None:
        """상대경로를 절대경로로 바꾸고, 프래그먼트(#) 등은 제거"""
        if not link or link.startswith(("mailto:", "javascript:", "tel:")):
            return None
        absolute = urljoin(base, link)
        absolute = absolute.split("#")[0]
        return absolute

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> list[FormInfo]:
        forms = []
        for form_tag in soup.find_all("form"):
            action = form_tag.get("action") or page_url
            action = self._normalize(page_url, action) or page_url
            method = (form_tag.get("method") or "GET").upper()
            inputs = [
                inp.get("name") for inp in form_tag.find_all(["input", "textarea", "select"])
                if inp.get("name")
            ]
            forms.append(FormInfo(action=action, method=method, inputs=inputs))
        return forms

    def _extract_links(self, soup: BeautifulSoup, page_url: str) -> list[str]:
        links = []
        for a_tag in soup.find_all("a", href=True):
            normalized = self._normalize(page_url, a_tag["href"])
            if normalized and self._is_same_domain(normalized):
                links.append(normalized)
        return links

    def fetch_page(self, url: str) -> tuple[PageInfo, list[str]]:
        """
        URL 하나를 실제로 요청해서 PageInfo로 변환.
        crawl()의 내부 로직이자, swagger 등 "링크로는 못 찾는" 시드 URL을
        동일한 방식으로 처리하기 위해 별도 메서드로 분리해둠.

        반환값: (PageInfo, 페이지에서 발견한 같은 도메인 링크 목록)
        요청 실패 시에도 None이 아니라 status_code=-1인 PageInfo를 반환한다
        (링크 목록은 빈 리스트).
        """
        try:
            resp = self.session.get(url, timeout=self.timeout)
        except requests.RequestException as e:
            print(f"[crawler] 요청 실패: {url} ({e})")
            return PageInfo(url=url, status_code=-1), []

        soup = BeautifulSoup(resp.text, "lxml")
        forms = self._extract_forms(soup, url)
        query_params = [p for p in urlparse(url).query.split("&") if p]

        page = PageInfo(
            url=url,
            status_code=resp.status_code,
            forms=forms,
            query_params=query_params,
        )
        links = self._extract_links(soup, url)
        return page, links

    def crawl(self) -> list[PageInfo]:
        """BFS 방식으로 크롤링하여 PageInfo 목록을 반환"""
        pages: list[PageInfo] = []
        queue: list[tuple[str, int]] = [(self.base_url, 0)]

        while queue:
            url, depth = queue.pop(0)
            if url in self.visited or depth > self.max_depth:
                continue
            self.visited.add(url)

            page, links = self.fetch_page(url)
            pages.append(page)

            if page.status_code == -1:
                continue

            for link in links:
                if link not in self.visited:
                    queue.append((link, depth + 1))

            time.sleep(self.delay)

        return pages

    def visit_extra(self, url: str) -> PageInfo | None:
        """
        크롤링(BFS)과 별개로, 이미 알고 있는 URL 하나를 결과 목록에 추가하고 싶을 때 사용.
        (예: swagger 문서에서 찾은, 어디서도 링크되지 않은 /vuln/* 라우트)
        이미 방문한 URL이면 중복 요청하지 않고 None을 반환.
        """
        if url in self.visited:
            return None
        self.visited.add(url)
        page, _links = self.fetch_page(url)
        time.sleep(self.delay)
        return page


if __name__ == "__main__":
    # 단독 실행 시 간단 테스트용
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    c = Crawler(target, max_depth=1)
    result = c.crawl()
    for p in result:
        print(p.url, p.status_code, f"forms={len(p.forms)}")
