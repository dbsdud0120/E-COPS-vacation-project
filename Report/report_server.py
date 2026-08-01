from flask import Flask, request, jsonify
import subprocess
import os
import sys

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Generator 및 Checker 스크립트 위치 정의
REPORT_GENERATOR = os.path.join(
    BASE_DIR,
    "report_generator.py"
)

DASHBOARD_GENERATOR = os.path.join(
    BASE_DIR,
    "dashboard_generator.py"
)

SECURITY_POLICY_CHECKER = os.path.join(
    BASE_DIR,
    "security_policy_checker.py"
)

POLICY_REPORT_GENERATOR = os.path.join(
    BASE_DIR,
    "policy_report_generator.py"
)


@app.route("/report", methods=["POST"])
def report():
    data = request.get_json()

    if not data:
        return jsonify({
            "error": "json body required"
        }), 400

    results = {}

    try:
        # ==========================================================
        # [사전 검증] json_path 유효성 먼저 체크
        # ==========================================================
        if "json_path" in data:
            json_path = data["json_path"]
            if not os.path.exists(json_path):
                return jsonify({
                    "error": "scanner json not found",
                    "path": json_path
                }), 404

        # ==========================
        # 1. 취약점 상세 리포트
        # ==========================
        if "json_path" in data:
            json_path = data["json_path"]
            report_prefix = os.path.join(
                os.path.dirname(json_path),
                "report"
            )

            subprocess.run(
                [
                    sys.executable,
                    REPORT_GENERATOR,
                    json_path,
                    report_prefix
                ],
                check=True
            )

            results["report"] = {
                "html": report_prefix + ".html",
                "pdf": report_prefix + ".pdf"
            }

            # ==========================
            # 2. Dashboard 생성
            # ==========================
            dashboard_prefix = os.path.join(
                os.path.dirname(json_path),
                "dashboard"
            )

            subprocess.run(
                [
                    sys.executable,
                    DASHBOARD_GENERATOR,
                    json_path,
                    dashboard_prefix
                ],
                check=True
            )

            results["dashboard"] = {
                "html": dashboard_prefix + ".html"
            }

        # ==========================
        # 3. 정책 점검 및 리포트 생성 (통합 처리)
        # ==========================
        if "policy_path" in data and "url" in data:
            policy_path = data["policy_path"]
            target_url = data["url"]

            # 3-1. security_policy_checker.py 실행 -> policy_result.json 생성
            subprocess.run(
                [
                    sys.executable,
                    SECURITY_POLICY_CHECKER,
                    target_url,
                    policy_path
                ],
                check=True
            )

            # 3-2. policy_report_generator.py 실행 -> policy_report.html 생성
            policy_prefix = os.path.join(
                os.path.dirname(policy_path),
                "policy_report"
            )

            subprocess.run(
                [
                    sys.executable,
                    POLICY_REPORT_GENERATOR,
                    policy_path,
                    policy_prefix
                ],
                check=True
            )

            results["policy"] = {
                "html": policy_prefix + ".html"
            }

    except subprocess.CalledProcessError as e:
        return jsonify({
            "error": "generation failed",
            "detail": str(e)
        }), 500

    return jsonify({
        "status": "completed",
        "results": results
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5002
    )
