"""
checks/xss_context.py
------------------------
xss.py / stored_xss.py가 공통으로 쓰는 "실행 가능한 문맥(exploitable context)"
판별 로직.

기존 방식(단순 substring 매칭: `payload in response.text`)의 문제:
  1. payload가 실제 HTML 마크업이 아니라, 에러 메시지 같은 순수 텍스트
     응답에 우연히 그대로 포함된 경우를 구분하지 못함
     (예: /vuln/download가 파일 오류 메시지에 파일명을 그대로 포함시키는 경우 ->
      <script> 태그처럼 생긴 문자열이 반사되긴 했지만 파일 경로 처리 실패
      메시지일 뿐, HTML/JS로 해석되는 위치가 아님)
  2. <, >, ", ' 같은 HTML 특수문자가 없는 payload(예: javascript:alert(1))가
     실제로 실행되는 위치(예: <a href="...">)가 아니라 그냥 평범한 텍스트로
     출력된 경우까지 "반사됨(그대로 노출됨)"으로 오판함
     (예: Jinja2 autoescape가 적용된 템플릿의 <p>{{ content }}</p>에
      javascript:alert(1)이 그대로 찍혀도, 이건 그냥 문자열이지 실행되는
      URI가 아님)

이 모듈은 완벽한 브라우저 시뮬레이션은 아니지만(DOM 기반 XSS까지는 커버하지
않음), 위 두 가지 흔한 오탐 패턴을 없애기 위해 최소한의 "실행 가능한 문맥"
검증을 추가한다:
  - payload를 제거한 나머지 응답에도 실제 HTML 태그가 남아 있는지
    (=이 응답이 실제로 렌더링되는 HTML 페이지인지, 그냥 텍스트인지)
  - payload가 만들어낸 게 실제 <script>/<img onerror>/<svg onload> 같은
    "실행되는" 노드인지, 아니면 그냥 <p>/<h3> 같은 일반 텍스트 위치에
    찍힌 문자열인지 (BeautifulSoup으로 파싱해서 확인)
  - javascript: URI나 on*= 이벤트 핸들러 payload는 실제로 href/src/on* 같은
    "실행되는 속성" 값으로 들어갔는지까지 확인
"""
from __future__ import annotations
import re

from bs4 import BeautifulSoup

# payload가 새로 만들어낼 수 있는, 그 자체로 실행 가능한 태그들
_EXECUTABLE_TAGS = ("script", "img", "svg", "iframe", "body", "input", "a", "video", "audio", "details")

# 이벤트 핸들러 속성 (onerror, onload, onmouseover 등)
_EVENT_ATTR_RE = re.compile(r"^on[a-z]+$", re.IGNORECASE)

# javascript: URI
_JS_URI_RE = re.compile(r"^\s*javascript:", re.IGNORECASE)

# URI를 값으로 받는, "실행"으로 이어질 수 있는 속성들
_URI_ATTRS = {"href", "src", "action", "formaction", "data"}

# 이 태그 안에 있으면 브라우저가 마크업/스크립트로 해석하지 않고 순수 텍스트로만 취급함
_NON_EXECUTING_PARENTS = {"textarea", "title", "template", "noscript"}

# HTML 태그처럼 생긴 부분을 찾기 위한 대략적인 패턴 (진짜 파서는 아니지만
# "이 응답에 태그가 하나라도 더 있는가"를 보는 용도로는 충분함)
_TAG_LIKE_RE = re.compile(r"<[a-zA-Z!][^<>]*>")


def _has_surrounding_markup(response_text: str, payload: str) -> bool:
    """payload 자체를 응답에서 제거한 나머지에도 실제 HTML 태그가 남아있는지 확인.

    남아있지 않다면, Content-Type이 text/html이더라도 사실상 이 응답은
    "렌더링되는 HTML 페이지"가 아니라 순수 텍스트(에러 메시지 등)라는 뜻이다.
    이 경우 payload에 포함된 <, > 문자가 반사되어도 브라우저가 실제로
    태그로 해석할 문맥 자체가 없다.
    """
    remainder = response_text.replace(payload, "")
    return bool(_TAG_LIKE_RE.search(remainder))


def _is_inside_html_comment(response_text: str, payload: str) -> bool:
    idx = response_text.find(payload)
    if idx == -1:
        return False
    comment_start = response_text.rfind("<!--", 0, idx)
    comment_end = response_text.rfind("-->", 0, idx)
    return comment_start != -1 and comment_start > comment_end


def _attr_value_to_str(value) -> str:
    return value if isinstance(value, str) else " ".join(value)


def _parse_payload_tag(payload: str):
    """payload 자체를 파싱해서 그것이 온전한 실행 가능 태그(<script>, <img ...> 등)를
    나타내는지 확인. 아니면 None.

    ⚠️ 응답 전체를 파싱한 뒤 'payload in str(tag)'처럼 문자열로 다시 비교하면,
    <body>처럼 페이지에 항상 존재하는 상위 태그의 재직렬화 결과에 하위 텍스트가
    전부 포함되어(=<body>...(그 안의 모든 텍스트)...</body>) payload가 실행되지
    않는 일반 텍스트로 들어간 경우조차 매칭되어버리는 오탐이 생긴다. 그래서 payload
    자체를 독립적으로 파싱해 "태그명 + 속성 + 텍스트" 시그니처를 뽑아두고, 응답에서
    찾은 후보 태그와 이 시그니처를 구조적으로 비교하는 방식을 쓴다.
    """
    try:
        p_soup = BeautifulSoup(payload, "html.parser")
    except Exception:
        return None
    return p_soup.find(_EXECUTABLE_TAGS)


def _tag_matches_payload_signature(payload_tag, candidate_tag) -> bool:
    if payload_tag.name != candidate_tag.name:
        return False
    # payload가 명시한 속성들은 후보 태그에도 (부분 일치 이상으로) 있어야 함
    for attr, value in payload_tag.attrs.items():
        cand_value = candidate_tag.attrs.get(attr)
        if cand_value is None:
            return False
        val_str = _attr_value_to_str(value).strip()
        cand_str = _attr_value_to_str(cand_value).strip()
        if val_str and val_str not in cand_str:
            return False
    # payload에 텍스트 내용이 있었다면(예: <script>alert(1)</script>) 후보 태그의
    # 텍스트에도 그대로 있어야 함
    payload_text = payload_tag.get_text(strip=True)
    if payload_text and payload_text not in candidate_tag.get_text():
        return False
    return True


def _payload_creates_executable_node(soup: BeautifulSoup, payload: str) -> bool:
    """파싱 결과에서 payload가 실제로 '실행되는' 위치에 반영됐는지 확인."""

    def parent_is_non_executing(tag) -> bool:
        parent_names = {p.name for p in tag.parents if getattr(p, "name", None)}
        return bool(parent_names & _NON_EXECUTING_PARENTS)

    # 1) payload 자체가 script/img/svg 등 그 자체로 실행되는 완전한 태그라면,
    #    응답에서 같은 태그명 + 속성 + 텍스트를 가진 노드가 실제로 만들어졌는지 확인
    payload_tag = _parse_payload_tag(payload)
    if payload_tag is not None:
        for tag in soup.find_all(payload_tag.name):
            if parent_is_non_executing(tag):
                continue
            if _tag_matches_payload_signature(payload_tag, tag):
                return True

    # 2) payload가 그 자체로 완전한 태그는 아니지만(예: javascript: URI,
    #    "onmouseover=... 같은 독립형 payload), 응답의 실제 태그 안에서
    #    "실행되는 속성"(이벤트 핸들러, href/src의 javascript: URI 등) 값으로
    #    들어갔는가
    for tag in soup.find_all(True):
        if parent_is_non_executing(tag):
            continue
        for attr_name, attr_value in tag.attrs.items():
            value = _attr_value_to_str(attr_value)

            if _EVENT_ATTR_RE.match(attr_name):
                # 속성 탈출형(attribute breakout) payload(예: '"onmouseover="alert(1)')는
                # 파서가 attr_name="onmouseover", value="alert(1)"로 따로 분리해버려서
                # "payload 문자열 전체가 value 안에 있는가"로는 못 잡는다. 대신 "이
                # 속성 이름과 값이 둘 다 payload 원문 안에 등장하는가"로 판단한다
                # (=이 속성 자체가 payload로 인해 새로 생겨났다는 신호).
                if attr_name in payload and (not value or value in payload):
                    return True
                continue

            if payload not in value:
                continue
            if attr_name.lower() in _URI_ATTRS and _JS_URI_RE.match(value.strip()):
                return True

    return False


def is_exploitable_reflection(response_text: str, payload: str, content_type: str | None = None) -> bool:
    """payload가 응답에 이스케이프 없이 포함되어 있을 뿐 아니라,
    브라우저가 실제로 실행할 수 있는 HTML 문맥에 반영되었는지까지 확인한다.

    True: payload 문자열 반사 + 실행 가능한 문맥까지 확인됨 (TP 가능성 높음)
    False: payload 문자열이 이스케이프됐거나(기존 로직과 동일), 반사는 됐지만
           실행되지 않는 문맥(순수 텍스트 응답, 일반 텍스트 위치 등)이라 오탐으로 제외
    """
    if payload not in response_text:
        return False

    if content_type and "html" not in content_type.lower():
        # HTML로 렌더링되지 않는 응답(JSON 등)은 브라우저가 마크업으로 해석하지 않음
        return False

    if _is_inside_html_comment(response_text, payload):
        return False

    if not _has_surrounding_markup(response_text, payload):
        return False

    try:
        soup = BeautifulSoup(response_text, "html.parser")
    except Exception:
        return False

    return _payload_creates_executable_node(soup, payload)
