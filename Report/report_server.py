from flask import Flask, request, jsonify
import subprocess
import os

app = Flask(__name__)


# Report 생성 파일 위치
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_GENERATOR = os.path.join(
    BASE_DIR,
    "report_generator.py"
)


@app.route("/report", methods=["POST"])
def report():

    data = request.get_json()

    if not data or "json_path" not in data:
        return jsonify({
            "error": "json_path is required"
        }), 400


    json_path = data["json_path"]


    # 전달받은 Scanner 결과 파일 존재 확인
    if not os.path.exists(json_path):
        return jsonify({
            "error": "JSON result file not found",
            "path": json_path
        }), 404



    # 결과 파일과 같은 위치에 report 생성
    report_prefix = os.path.join(
        os.path.dirname(json_path),
        "report"
    )


    try:

        subprocess.run(
            [
                "python",
                REPORT_GENERATOR,
                json_path,
                report_prefix
            ],
            check=True
        )


    except subprocess.CalledProcessError as e:

        return jsonify({
            "error": "Report generation failed",
            "detail": str(e)
        }), 500



    return jsonify({

        "status": "completed",

        "html": report_prefix + ".html",

        "pdf": report_prefix + ".pdf"

    })



if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5002
    )
