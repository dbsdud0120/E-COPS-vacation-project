"""
swagger_seed.py
-----------------
crawler가 <a href="">로 발견하지 못하는 라우트(index.html/posts.html 등에
링크가 없는 /vuln/* 라우트 등)를 Swagger(OpenAPI) 문서에서 읽어와
크롤링 결과에 추가하기 위한 헬퍼.

두 가지 입력을 지원:
  1. 로컬 파일 경로 (예: ../Backend/swagger.yaml) - 지금 당장 사용 가능.
     Scanner와 Backend가 같은 레포에 있다는 전제.
  2. http(s) URL - Backend가 나중에 /swagger.json 같은 라우트로 노출해주면
     로컬 파일 대신 그 URL을 그대로 넘기면 됩니다 (동작 동일).

⚙️ Backend가 스펙에 없는 새 /vuln/* 라우트를 추가하면, 이 파일은 수정할 필요 없이
   swagger.yaml/json만 최신으로 유지되면 자동으로 잡힙니다.
"""
from __future__ import annotations
import json
from urllib.parse import urljoin

import requests
import yaml

# path 파라미터(예: {post_id})를 채울 때 쓸 기본값
DEFAULT_PATH_PARAM_VALUE = "1"

# 쿼리 파라미터가 필요한 GET 엔드포인트는 예시 값을 붙여줘야
# directory_traversal 같은 쿼리 파라미터 기반 검사가 바로 테스트할 수 있음
# TODO(Backend가 파라미터 이름을 바꾸면): 여기 키를 맞춰서 수정
DEFAULT_QUERY_PARAMS = {
    "/vuln/download": "file=test.txt",
    # /vuln/comment는 GET 쿼리 파라미터(text)를 그대로 escaping 없이 출력하는
    # Reflected XSS 시연 라우트인데, 예시 쿼리 파라미터가 없으면 xss.py의
    # "이미 URL에 있는 쿼리 파라미터만 테스트하는" 로직이 테스트할 대상 자체를
    # 찾지 못해 findings가 0건으로 나오는 문제가 있었음.
    "/vuln/comment": "text=test",
}


def load_seed_urls(source: str, base_url: str) -> list[str]:
    """
    source: swagger.yaml/json의 로컬 파일 경로 또는 http(s) URL
    base_url: 스캔 대상 서버 (예: http://localhost:5000)
    반환: 크롤링 시드로 추가할 절대 URL 목록 (GET 가능한 경로만)
    """
    spec = _load_spec(source)
    if not spec:
        return []

    paths = spec.get("paths", {})
    urls = []

    for path, methods in paths.items():
        method_names = {m.lower() for m in methods.keys()}
        if "get" not in method_names:
            continue  # POST/DELETE 전용 엔드포인트는 크롤링(GET) 시드 대상이 아님

        resolved_path = path
        for param_name in _extract_path_param_names(path):
            resolved_path = resolved_path.replace(
                "{" + param_name + "}", DEFAULT_PATH_PARAM_VALUE
            )

        if resolved_path in DEFAULT_QUERY_PARAMS:
            resolved_path = f"{resolved_path}?{DEFAULT_QUERY_PARAMS[resolved_path]}"

        urls.append(urljoin(base_url, resolved_path))

    return urls


def load_post_form_seeds(source: str, base_url: str) -> list[dict]:
    """
    GET이 없는(POST 전용) 엔드포인트 중 requestBody가 폼 형태(application/x-www-form-urlencoded)로
    문서화된 것들을 찾아 "가상 페이지" 정보로 반환한다.

    ⚠️ 왜 필요한가:
    /vuln/login, /api/token 같은 라우트는 GET이 없어서 load_seed_urls()의 대상이 아니고,
    어떤 HTML 페이지에도 <form action="...">으로 링크되어 있지 않다. 그래서 크롤러가
    실제로 이 URL을 "방문"할 방법이 아예 없었고, sql_injection.py/xss.py처럼
    "page.forms에 있는 POST 폼을 테스트"하는 check들이 이 라우트들을 영원히 못 봤다.

    이 함수는 실제 HTTP 요청 없이(=GET으로 확인할 수 없으므로) swagger 문서에 적힌
    필드 이름만으로 "이런 폼이 있다고 치자"는 가상의 폼 정보를 만들어서, scanner.py가
    crawler.PageInfo/FormInfo로 조립해 pages 목록에 끼워 넣을 수 있게 해준다.
    이렇게 하면 기존 check 코드(sql_injection.py 등)는 전혀 수정할 필요가 없다 —
    check들은 "page.forms에 POST 폼이 있으면 테스트한다"는 로직을 이미 갖고 있기 때문.

    반환값: [{"path": "/vuln/login", "url": "http://.../vuln/login", "inputs": ["username","password"]}, ...]
    """
    spec = _load_spec(source)
    if not spec:
        return []

    paths = spec.get("paths", {})
    seeds = []

    for path, methods in paths.items():
        method_names = {m.lower() for m in methods.keys()}
        if "get" in method_names or "post" not in method_names:
            continue  # GET이 있으면 load_seed_urls가 이미 커버함. POST가 없으면 대상 아님.

        post_spec = methods["post"] or {}
        inputs = _extract_form_field_names(post_spec)
        if not inputs:
            # requestBody가 아예 문서화 안 되어 있으면 어떤 필드를 채워야 할지 알 수 없어 건너뜀
            print(
                f"[swagger_seed] 경고: '{path}'는 POST 전용인데 requestBody가 "
                f"문서화되어 있지 않아 건너뜁니다 (swagger.yaml에 필드 추가 필요)"
            )
            continue

        seeds.append({
            "path": path,
            "url": urljoin(base_url, path),
            "inputs": inputs,
        })

    return seeds


def _extract_form_field_names(post_spec: dict) -> list[str]:
    """OpenAPI 3 requestBody의 application/x-www-form-urlencoded 스키마에서 필드 이름 목록 추출"""
    try:
        schema = (
            post_spec["requestBody"]["content"]
            ["application/x-www-form-urlencoded"]["schema"]
        )
        return list(schema.get("properties", {}).keys())
    except (KeyError, TypeError):
        return []


def _extract_path_param_names(path: str) -> list[str]:
    """'/posts/{post_id}/edit' -> ['post_id']"""
    names = []
    depth_start = None
    for i, ch in enumerate(path):
        if ch == "{":
            depth_start = i + 1
        elif ch == "}" and depth_start is not None:
            names.append(path[depth_start:i])
            depth_start = None
    return names


def _load_spec(source: str) -> dict | None:
    try:
        if source.startswith("http://") or source.startswith("https://"):
            resp = requests.get(source, timeout=5)
            text = resp.text
        else:
            with open(source, "r", encoding="utf-8") as f:
                text = f.read()
    except Exception as e:
        print(f"[swagger_seed] 스펙 로드 실패 ({source}): {e}")
        return None

    try:
        if source.endswith(".json"):
            return json.loads(text)
        return yaml.safe_load(text)  # .yaml/.yml
    except Exception as e:
        print(f"[swagger_seed] 스펙 파싱 실패 ({source}): {e}")
        return None
