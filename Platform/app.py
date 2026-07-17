from flask import Flask, render_template, request, send_file
import subprocess
import os
import glob


app = Flask(__name__)


# Scanner가 생성한 가장 최근 결과(JSON) 찾기
def get_latest_result():

    # scan_*.json 파일 목록 조회
    files = glob.glob("/app/results/scan_*.json")

    # 결과가 없으면 None 반환
    if not files:
        return None

    # 가장 최근 생성된 파일 반환
    return max(files, key=os.path.getmtime)


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

        # 상태 변경
        scan_status["status"] = "Generating Report..."

        # 최신 결과 파일 찾기
        result_file = get_latest_result()

        if result_file is None:
            return "Scan result not found"


        # Report 실행 (최신 JSON 파일 경로 전달)
        subprocess.run(
            [
                "python",
                "/app/report/report.py",
                result_file
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
