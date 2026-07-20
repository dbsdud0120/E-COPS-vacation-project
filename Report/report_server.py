from flask import Flask, request, jsonify
import subprocess
import os

app = Flask(__name__)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# Report 생성기 위치
REPORT_GENERATOR = os.path.join(
    BASE_DIR,
    "report_generator.py"
)

DASHBOARD_GENERATOR = os.path.join(
    BASE_DIR,
    "dashboard_generator.py"
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

        # ==========================
        # 1. 취약점 상세 리포트
        # ==========================

        if "json_path" in data:

            json_path = data["json_path"]


            if not os.path.exists(json_path):
                return jsonify({
                    "error": "scanner json not found",
                    "path": json_path
                }), 404


            report_prefix = os.path.join(
                os.path.dirname(json_path),
                "report"
            )


            subprocess.run(
                [
                    "python",
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
                    "python",
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
        # 3. 정책 점검 리포트
        # ==========================

        if "policy_path" in data:

            policy_path = data["policy_path"]


            if not os.path.exists(policy_path):
                return jsonify({
                    "error": "policy json not found",
                    "path": policy_path
                }),404



            policy_prefix = os.path.join(
                os.path.dirname(policy_path),
                "policy_report"
            )


            subprocess.run(
                [
                    "python",
                    POLICY_REPORT_GENERATOR,
                    policy_path,
                    policy_prefix
                ],
                check=True
            )


            results["policy_report"] = {
                "html": policy_prefix + ".html"
            }



    except subprocess.CalledProcessError as e:

        return jsonify({
            "error": "generation failed",
            "detail": str(e)
        }),500



    return jsonify({
        "status": "completed",
        "results": results
    })



if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5002
    )
