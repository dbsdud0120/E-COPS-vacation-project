"""
checks/jwt_verification.py
----------------------------
JWT 서명 검증 누락(Missing JWT Verification) 탐지. (3주차 추가)

동작 방식:
  1. 대상 페이지 응답(쿠키, 응답 바디, Authorization류 헤더)에서 JWT처럼 생긴 문자열
     (header.payload.signature, header 파트가 base64url JSON이고 "alg" 키를 포함)을 찾는다.
  2. 찾은 토큰마다 두 가지 변조 토큰을 만든다.
       a) alg을 "none"으로 바꾸고 서명을 제거한 토큰 (alg=none 공격)
       b) 서명(signature) 마지막 문자를 임의로 바꾼(위조) 토큰
  3. 각 변조 토큰을 "쿠키 없는 새 세션"으로 Authorization: Bearer 헤더에 실어 같은 URL에 요청하고,
     "쿠키/토큰이 전혀 없는 요청(익명 요청)"과 응답을 비교한다.
     -> 변조 토큰만으로도 익명 요청과 다르게(=인증된 것처럼) 200 응답을 받으면
        "서명을 검증하지 않는다"로 판단해 기록한다.
  4. exp(만료시간) 클레임이 없는 토큰은 별도로 낮은 심각도(LOW)로 기록한다.

⚠️ 반드시 "쿠키 없는" 별도 세션으로 변조 토큰을 테스트한다. scanner.py가 넘겨주는 session은
   이미 로그인된 쿠키를 들고 있을 수 있어서, 그 session을 그대로 쓰면 토큰과 무관하게 쿠키만으로
   통과되어 오탐(false positive)이 날 수 있기 때문이다.

⚠️ 현재(3주차 시점) Backend(app.py)는 세션 쿠키 기반 인증만 사용하고 JWT를 쓰지 않는다.
   이 Backend를 대상으로 스캔하면 대부분 findings가 0건인 게 정상이다.
   (다른 JWT 기반 백엔드를 스캔할 때를 대비한 범용 검사.)

⚙️ Backend가 JWT를 도입하면:
   - 로그인 응답 바디/쿠키/헤더에 토큰을 포함시키기만 하면 이 check가 자동으로 찾아서 검사함.
   - 토큰이 특정 커스텀 헤더에만 있다면 EXTRA_HEADER_NAMES에 추가.

⚠️ 알려진 한계: 이 check는 다른 checks와 동일하게 (session, page, payloads) 시그니처로
   "페이지 1개" 단위로 동작한다. 즉 토큰을 발견한 그 페이지 자체에 변조 토큰을 재요청해서
   테스트하며, "토큰은 A 페이지에서 발급되고 실제 보호되는 리소스는 B 페이지"처럼
   발급/사용 페이지가 분리된 경우는 잡아내지 못한다 (검증 완료: 실제로 서명을 검증하지
   않는 엔드포인트에 변조 토큰을 보내면 200이 반환되는 것을 목업 서버로 확인함 -
   다만 그 목업처럼 토큰 발급과 검증 엔드포인트가 다르면 크롤러가 각 페이지를 따로
   방문하는 현재 구조상 자동으로는 연결되지 않음). 이런 케이스까지 잡으려면 "발견한
   토큰을 다른 페이지들에도 재사용해서 테스트"하도록 scanner.py 쪽에서 토큰을 여러
   check 호출 간에 공유하는 구조 변경이 필요하며, 이는 이번 3주차 범위를 벗어나
   TODO로 남겨둔다.
"""
from __future__ import annotations
import base64
import json
import re

import requests as _requests

from checks.base import Finding, Severity, make_finding

CHECK_NAME = "missing_jwt_verification"

# header.payload.signature 형태 (각 파트는 base64url 문자셋, 패딩 '=' 없음)
JWT_PATTERN = re.compile(r"\b([A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})\b")

# 토큰을 찾을 추가 응답 헤더 (표준은 아니지만 커스텀 백엔드 대비)
EXTRA_HEADER_NAMES = ("Authorization", "X-Auth-Token", "X-Access-Token")


def _b64url_decode(segment: str) -> bytes | None:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return None


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _looks_like_jwt(token: str) -> dict | None:
    """header 파트가 실제 JWT 헤더(JSON + 'alg' 키)로 디코딩되면 header dict를, 아니면 None을 반환.
    (Flask의 session 쿠키 등 dot이 2개 섞인 다른 형식의 값을 오탐하지 않기 위한 필터)"""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    raw = _b64url_decode(parts[0])
    if raw is None:
        return None
    try:
        header = json.loads(raw)
    except Exception:
        return None
    if not isinstance(header, dict) or "alg" not in header:
        return None
    return header


def _find_tokens(resp) -> list[str]:
    candidates: set[str] = set()

    for cookie in resp.cookies:
        candidates.add(cookie.value)

    for header_name in EXTRA_HEADER_NAMES:
        value = resp.headers.get(header_name)
        if value:
            candidates.add(value.replace("Bearer ", "").strip())

    candidates.update(JWT_PATTERN.findall(resp.text))

    return [t for t in candidates if _looks_like_jwt(t) is not None]


def _tamper_alg_none(token: str) -> str:
    header_b64, payload_b64, _sig = token.split(".")
    header = json.loads(_b64url_decode(header_b64))
    header["alg"] = "none"
    new_header_b64 = _b64url_encode(json.dumps(header).encode())
    return f"{new_header_b64}.{payload_b64}."


def _tamper_signature(token: str) -> str:
    header_b64, payload_b64, sig_b64 = token.split(".")
    if not sig_b64:
        return f"{header_b64}.{payload_b64}.AAAAAAAAAAAAAAAA"
    flipped = "A" if sig_b64[-1] != "A" else "B"
    return f"{header_b64}.{payload_b64}.{sig_b64[:-1]}{flipped}"


def _payload_claims(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    raw = _b64url_decode(parts[1])
    if raw is None:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _clean_get(url: str, headers: dict | None = None, timeout: int = 5):
    """쿠키를 전혀 들고 있지 않은 새 세션으로 요청 (변조 토큰만의 효과를 격리해서 확인하기 위함)"""
    with _requests.Session() as s:
        return s.get(url, headers=headers or {}, timeout=timeout)


def run(session, page, payloads: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    if page.status_code == -1:
        return findings

    try:
        baseline = session.get(page.url, timeout=5)
    except Exception:
        return findings

    tokens = _find_tokens(baseline)
    if not tokens:
        return findings  # 이 페이지에서 JWT를 발견하지 못함 (검사 대상 아님)

    try:
        anonymous = _clean_get(page.url)
    except Exception:
        return findings

    for token in tokens:
        header = _looks_like_jwt(token)
        claims = _payload_claims(token)

        if "exp" not in claims:
            findings.append(make_finding(
                check_name=CHECK_NAME,
                url=page.url,
                parameter="Authorization",
                payload=None,
                severity=Severity.LOW,
                evidence=f"발견된 JWT에 만료시간(exp) 클레임이 없음 (header={header})",
                description="토큰에 만료시간이 없어, 한 번 탈취되면 무기한 재사용될 수 있습니다.",
            ))

        for tamper_name, tamper_fn in (
            ("alg=none 공격", _tamper_alg_none),
            ("서명 변조", _tamper_signature),
        ):
            try:
                tampered = tamper_fn(token)
            except Exception:
                continue

            try:
                tampered_resp = _clean_get(page.url, headers={"Authorization": f"Bearer {tampered}"})
            except Exception:
                continue

            # 쿠키 없이 "변조된 토큰"만 실어서 요청했는데도, 익명 요청과 다르게 정상(200) 응답이면
            # 서버가 서명을 검증하지 않고 토큰 내용을 그대로 신뢰하는 것으로 판단
            if tampered_resp.status_code == 200 and tampered_resp.status_code != anonymous.status_code:
                findings.append(make_finding(
                    check_name=CHECK_NAME,
                    url=page.url,
                    parameter="Authorization",
                    payload=tampered,
                    severity=Severity.CRITICAL,
                    evidence=(
                        f"{tamper_name}한 토큰만 실어 쿠키 없이 요청해도 정상 응답(200)이 반환됨 "
                        f"(익명 요청은 {anonymous.status_code})"
                    ),
                    description="API 서버가 JWT의 서명을 검증하지 않아, 토큰을 임의로 조작해 인증을 우회할 수 있습니다.",
                ))
                break  # 토큰당 1건만 기록

    return findings
