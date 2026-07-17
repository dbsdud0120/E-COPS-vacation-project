from flask import Flask, render_template, request, send_file, jsonify
import subprocess
import os
import uuid
import threading


app = Flask(__name__)


# 결과 저장 기본 경로
RESULTS_DIR = "/app/results"


# 작업별 상태 저장
# 예:
# {
#   "job_id": {
#       "status": "Scanning",
#       "url": "http://test.com"
#   }
# }
scan_jobs = {}



# Scanner + Report 실행 함수
def run_scan_job(job_id, url):

    result_dir = os.path.join(
        RESULTS_DIR,
        job_id
    )

    os.makedirs(
        result_dir,
        exist_ok=True
    )


    try:

        # Scanner 실행 상태
        scan_jobs[job_id]["status"] = "Scanning"


        # Scanner 실행
        subprocess.run(
            [
                "python",
                "/app/scanner/scanner.py",
                url
            ],
            check=True,
            cwd="/app/scanner"
        )


        # Scanner 결과 파일 찾기
        files = [
            f for f in os.listdir(RESULTS_DIR)
            if f.endswith(".json")
        ]


        if not files:
            raise Exception("Scan result not found")


        latest_file = max(
            [
                os.path.join(RESULTS_DIR, f)
                for f in files
            ],
            key=os.path.getmtime
        )


        # 결과 파일 이동
        json_path = os.path.join(
            result_dir,
            "scan.json"
        )


        os.rename(
            latest_file,
            json_path
        )


        # Report 실행 상태
        scan_jobs[job_id]["status"] = "Generating Report"


        # Report 실행
        subprocess.run(
            [
                "python",
                "/app/report/report.py",
                json_path
            ],
            check=True,
            cwd="/app/report"
        )


        scan_jobs[job_id]["status"] = "Completed"


    except Exception as e:

        scan_jobs[job_id]["status"] = "Error"
        scan_jobs[job_id]["error"] = str(e)



# 메인 페이지
@app.route("/")
def index():

    return render_template(
        "index.html"
    )



# Scan 요청
@app.route("/scan", methods=["POST"])
def scan():

    url = request.form.get("url")


    if not url:
        return "URL is required"


    # 작업 ID 생성
    job_id = str(uuid.uuid4())


    scan_jobs[job_id] = {
        "status": "Ready",
        "url": url
    }


    # 백그라운드 실행
    thread = threading.Thread(
        target=run_scan_job,
        args=(job_id, url)
    )


    thread.start()


    return jsonify(
        {
            "job_id": job_id,
            "status": "Started"
        }
    )



# Scan 상태 확인
@app.route("/status/<job_id>")
def status(job_id):

    if job_id not in scan_jobs:
        return jsonify(
            {
                "error": "Job not found"
            }
        )


    return jsonify(
        scan_jobs[job_id]
    )



# HTML Report 다운로드
@app.route("/download/html/<job_id>")
def download_html(job_id):

    path = os.path.join(
        RESULTS_DIR,
        job_id,
        "report.html"
    )


    if not os.path.exists(path):
        return "HTML report not found"


    return send_file(
        path,
        as_attachment=True
    )



# PDF Report 다운로드
@app.route("/download/pdf/<job_id>")
def download_pdf(job_id):

    path = os.path.join(
        RESULTS_DIR,
        job_id,
        "report.pdf"
    )


    if not os.path.exists(path):
        return "PDF report not found"


    return send_file(
        path,
        as_attachment=True
    )



if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8080
    )
