# -*- coding: utf-8 -*-
"""
security_policy_checker.py  (3주차 선택 기능: 보안 정책 점검)

OWASP Top 10 / OWASP ASVS 체크리스트 중, 대상 서버에 실제 HTTP 요청을 보내서
"자동으로" 확인 가능한 항목들을 점검한다.

자동으로 확인 가능한 것 (실제로 요청을 보내서 응답을 분석):
    - HTTPS 사용 여부 (http로 접속 시 https로 강제 리다이렉트 되는지)
    - 주요 Security Header 존재 여부
        (Strict-Transport-Security, X-Content-Type-Options,
         X-Frame-Options, Content-Security-Policy, Referrer-Policy)
    - CORS 설정 (Access-Control-Allow-Origin이 '*'로 열려있고
      동시에 Credentials까지 허용하는 위험한 조합인지)
    - JWT 만료시간 (--jwt 옵션으로 실제 토큰 문자열을 주면, 서명 검증 없이
      exp(만료시간) 클레임만 디코딩해서 존재 여부/만료 여부 확인)

자동으로 확인이 어려운 것 (사람이 직접 확인해야 하는 항목 -> "Manual"로 표시):
    - Password Policy (회원가입/로그인 폼 정책은 코드나 정책 문서를 봐야 알 수 있음)

사용법:
    python3 security_policy_checker.py <대상_URL> [출력_json_이름] [--jwt <토큰문자열>]

예시:
    python3 security_policy_checker.py http://test-server.local policy_result.json
    python3 security_policy_checker.py http://test-server.local policy_result.json --jwt eyJhbGciOi...
"""

import sys
import json
import time
from urllib.parse import urlparse

import requests

try:
    import jwt as pyjwt  # PyJWT
    HAS_PYJWT = True
except ImportError:
    HAS_PYJWT = False


SECURITY_HEADERS = {
    "Strict-Transport-Security": "HTTPS 강제 및 다운그레이드 공격 방지",
    "X-Content-Type-Options": "브라우저의 MIME 타입 스니핑으로 인한 공격 방지",
    "X-Frame-Options": "클릭재킹(다른 사이트에 내 페이지를 iframe으로 심는 공격) 방지",
    "Content-Security-Policy": "XSS 등 악성 스크립트 실행 범위 제한",
    "Referrer-Policy": "다른 사이트로 이동할 때 URL 정보 과다 노출 방지",
}


def check_https(url: str) -> dict:
    parsed = urlparse(url)
    http_url = f"http://{parsed.netloc}{parsed.path or '/'}"

    try:
        resp = requests.get(http_url, timeout=5, allow_redirects=True)
        final_scheme = urlparse(resp.url).scheme
        if final_scheme == "https":
            return {
                "id": "https_enforced",
                "name": "HTTPS 강제 여부",
                "status": "Pass",
                "detail": f"http 접속 시 {resp.url} 로 자동 리다이렉트됨",
                "recommendation": "-",
            }
        else:
            return {
                "id": "https_enforced",
                "name": "HTTPS 강제 여부",
                "status": "Fail",
                "detail": "http로 접속해도 https로 강제 전환되지 않음 (평문 통신 가능)",
                "recommendation": "웹 서버/로드밸런서 설정에서 http 요청을 https로 301 리다이렉트하도록 강제해야 함",
            }
    except requests.exceptions.RequestException as e:
        return {
            "id": "https_enforced",
            "name": "HTTPS 강제 여부",
            "status": "Error",
            "detail": f"요청 실패: {e}",
            "recommendation": "대상 서버가 켜져 있는지, 주소가 올바른지 확인 필요",
        }


def check_security_headers(url: str) -> list:
    results = []
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        headers = resp.headers
        for name, purpose in SECURITY_HEADERS.items():
            if name in headers:
                results.append({
                    "id": f"header_{name.lower().replace('-', '_')}",
                    "name": f"{name} 헤더",
                    "status": "Pass",
                    "detail": f"값: {headers[name]}",
                    "recommendation": "-",
                })
            else:
                results.append({
                    "id": f"header_{name.lower().replace('-', '_')}",
                    "name": f"{name} 헤더",
                    "status": "Fail",
                    "detail": f"헤더 없음 ({purpose} 기능이 없음)",
                    "recommendation": f"응답에 '{name}' 헤더를 추가해야 함",
                })
    except requests.exceptions.RequestException as e:
        results.append({
            "id": "header_check_error",
            "name": "Security Header 점검",
            "status": "Error",
            "detail": f"요청 실패: {e}",
            "recommendation": "대상 서버 상태 확인 필요",
        })
    return results


def check_cors(url: str) -> dict:
    try:
        resp = requests.get(
            url, timeout=5, allow_redirects=True,
            headers={"Origin": "https://evil-example.com"},
        )
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials")

        if acao == "*" and acac == "true":
            status, detail = "Fail", (
                "Access-Control-Allow-Origin: * 이면서 "
                "Access-Control-Allow-Credentials: true 로 설정되어 있음 "
                "(임의의 외부 사이트가 사용자 인증정보를 포함해 요청 가능한 위험한 조합)"
            )
        elif acao == "*":
            status, detail = "Warning", "Access-Control-Allow-Origin이 '*'로 모든 출처에 열려 있음"
        elif acao:
            status, detail = "Pass", f"허용된 출처가 명시적으로 제한되어 있음: {acao}"
        else:
            status, detail = "Pass", "CORS 헤더가 없음 (기본적으로 교차 출처 요청 차단됨)"

        return {
            "id": "cors_policy",
            "name": "CORS 설정",
            "status": status,
            "detail": detail,
            "recommendation": "-" if status == "Pass" else "허용 출처(Origin)를 화이트리스트로 명시적으로 제한해야 함",
        }
    except requests.exceptions.RequestException as e:
        return {
            "id": "cors_policy",
            "name": "CORS 설정",
            "status": "Error",
            "detail": f"요청 실패: {e}",
            "recommendation": "대상 서버 상태 확인 필요",
        }


def check_jwt_expiry(token: str) -> dict:
    if not token:
        return {
            "id": "jwt_expiry",
            "name": "JWT 만료시간(exp) 설정",
            "status": "Manual",
            "detail": "--jwt 옵션으로 토큰을 전달하지 않아 자동 점검을 건너뜀",
            "recommendation": "실제 로그인 후 발급받은 JWT를 --jwt 옵션으로 넣어 재실행하면 자동 확인 가능",
        }
    if not HAS_PYJWT:
        return {
            "id": "jwt_expiry",
            "name": "JWT 만료시간(exp) 설정",
            "status": "Error",
            "detail": "PyJWT 라이브러리가 설치되어 있지 않음 (pip install pyjwt 필요)",
            "recommendation": "-",
        }

    try:
        # 서명 검증은 하지 않고(비밀키를 모르므로) exp 클레임만 확인
        payload = pyjwt.decode(token, options={"verify_signature": False})
        exp = payload.get("exp")
        if exp is None:
            return {
                "id": "jwt_expiry",
                "name": "JWT 만료시간(exp) 설정",
                "status": "Fail",
                "detail": "토큰에 exp(만료시간) 클레임이 없음 -> 토큰이 영구적으로 유효할 수 있음",
                "recommendation": "JWT 발급 시 반드시 exp 클레임을 짧은 유효시간으로 설정해야 함",
            }
        remaining = exp - time.time()
        if remaining > 60 * 60 * 24:  # 24시간 이상 남았으면 과도하게 길다고 판단
            return {
                "id": "jwt_expiry",
                "name": "JWT 만료시간(exp) 설정",
                "status": "Warning",
                "detail": f"만료까지 약 {int(remaining/3600)}시간 남음 (유효기간이 과도하게 김)",
                "recommendation": "JWT 유효기간을 짧게(예: 15분~1시간) 설정하고 Refresh Token으로 갱신하는 구조 권장",
            }
        return {
            "id": "jwt_expiry",
            "name": "JWT 만료시간(exp) 설정",
            "status": "Pass",
            "detail": f"만료까지 약 {int(remaining/60)}분 남음",
            "recommendation": "-",
        }
    except Exception as e:
        return {
            "id": "jwt_expiry",
            "name": "JWT 만료시간(exp) 설정",
            "status": "Error",
            "detail": f"토큰 디코딩 실패: {e}",
            "recommendation": "--jwt 값이 올바른 JWT 형식인지 확인",
        }


def check_password_policy_manual() -> dict:
    return {
        "id": "password_policy",
        "name": "Password Policy",
        "status": "Manual",
        "detail": "회원가입/비밀번호 변경 로직은 자동 점검 대상이 아님",
        "recommendation": (
            "다음을 코드/정책 문서에서 직접 확인: "
            "최소 길이(8자 이상), 복잡도(대소문자/숫자/특수문자 조합), "
            "이전 비밀번호 재사용 금지, 로그인 실패 횟수 제한과의 연동 여부"
        ),
    }


def run_policy_check(target_url: str, jwt_token: str = "") -> dict:
    checklist = []
    checklist.append(check_https(target_url))
    checklist.extend(check_security_headers(target_url))
    checklist.append(check_cors(target_url))
    checklist.append(check_jwt_expiry(jwt_token))
    checklist.append(check_password_policy_manual())

    counts = {"Pass": 0, "Fail": 0, "Warning": 0, "Manual": 0, "Error": 0}
    for item in checklist:
        counts[item["status"]] = counts.get(item["status"], 0) + 1

    return {
        "target": target_url,
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": counts,
        "checklist": checklist,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("사용법: python3 security_policy_checker.py <대상_URL> [출력_json_이름] [--jwt <토큰>]")
        sys.exit(1)

    target = sys.argv[1]
    out_name = "policy_result.json"
    jwt_arg = ""

    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--jwt" and i + 1 < len(args):
            jwt_arg = args[i + 1]
            i += 2
        else:
            out_name = args[i]
            i += 1

    result = run_policy_check(target, jwt_arg)

    with open(out_name, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"[완료] 점검 결과 저장: {out_name}")
    print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
