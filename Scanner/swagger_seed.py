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
