from flask import Flask, render_template, request, send_file
import subprocess
import os
import time


app = Flask(__name__)


# 결과 파일 위치
RESULT_PATH = "/app/results/latest.json"


# 현재 진행 상태 저장
scan_status = {
    "status": "Ready"
}


# 메인 화면
@app.route("/")
def index():
    return render_template(
        "index.html",
        status=scan_status["status"]
    )


# Scan 실행
@app.route("/scan", methods=["POST"])
def scan():

    url = request.form["url"]

    try:

        # 상태 변경
        scan_status["status"] = "Scanning..."


        # Scanner 실행
        subprocess.run(
            [
                "python",
                "/app/scanner/scanner.py",
                url
            ],
            check=True
        )


        # 결과 파일 생성 확인
        scan_status["status"] = "Generating Report..."


        if not os.path.exists(RESULT_PATH):
            return "Scan result not found"


        # Report 실행
        subprocess.run(
            [
                "python",
                "/app/report/report.py"
            ],
            check=True
        )


        scan_status["status"] = "Completed"


        return render_template(
            "result.html"
        )


    except Exception as e:

        scan_status["status"] = "Error"

        return str(e)



# HTML Report 다운로드
@app.route("/download/html")
def download_html():

    return send_file(
        "/app/results/report.html",
        as_attachment=True
    )


# PDF Report 다운로드
@app.route("/download/pdf")
def download_pdf():

    return send_file(
        "/app/results/report.pdf",
        as_attachment=True
    )



if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8080
    )
