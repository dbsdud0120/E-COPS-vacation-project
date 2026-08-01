from flask import Flask, render_template, request, send_file, jsonify, redirect
import subprocess
import os
import uuid
import threading
import requests


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

        scan_response = requests.post(
            "http://scanner:5001/scan",
            json={
                "url": url,
                "job_id": job_id
            },
            timeout=300
        )

        scan_result = scan_response.json()

        json_path = scan_result["json_path"]


        # Report 실행 상태
        scan_jobs[job_id]["status"] = "Generating Report"

        
        
        report_response = requests.post(
            "http://report:5002/report",
            json={
                "url": url,
                "json_path": json_path
            },
            timeout=180
        )

        report_result = report_response.json()

        if report_response.status_code != 200 or "results" not in report_result:
            raise RuntimeError(
                f"report generation failed: {report_result}"
            )

        # 생성된 Report 경로는 Report 서버가 실제로 만든 경로를 그대로 사용한다.
        # (기존에는 json_path 문자열에 없는 "result.json"을 replace하려고 해서
        #  항상 원래 json_path가 그대로 남아있는 버그가 있었음)
        report_paths = report_result["results"]["report"]
        scan_jobs[job_id]["html"] = report_paths["html"]
        scan_jobs[job_id]["pdf"] = report_paths["pdf"]

        # ----------------------------------------------------
        # [추가] 종합 대시보드(dashboard) 경로 불러오기
        # ----------------------------------------------------
        if "dashboard" in report_result["results"]:
            dashboard_paths = report_result["results"]["dashboard"]
            scan_jobs[job_id]["dashboard_html"] = dashboard_paths["html"]

        # ----------------------------------------------------
        # [추가] 보안 정책 점검 리포트(policy_report) 경로 불러오기
        # ----------------------------------------------------
        if "policy_report" in report_result["results"]:
            policy_paths = report_result["results"]["policy_report"]
            scan_jobs[job_id]["policy_html"] = policy_paths["html"]



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
        args=(job_id, url),
        daemon=True
    )


    thread.start()


    # 결과 페이지 이동
    return redirect(
        f"/result/{job_id}"
    )

# 결과 화면
@app.route("/result/<job_id>")
def result(job_id):

    if job_id not in scan_jobs:
        return "Job not found"


    return render_template(
        "result.html",
        job_id=job_id,
        status=scan_jobs[job_id]["status"]
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

# 종합 대시보드(Dashboard) HTML 다운로드 및 조회
@app.route("/download/dashboard/<job_id>")
def download_dashboard(job_id):
    path = os.path.join(
        RESULTS_DIR,
        job_id,
        "dashboard.html"
    )

    if not os.path.exists(path):
        return "Dashboard HTML not found", 404

    return send_file(
        path,
        as_attachment=True
    )

# 보안 정책 점검(Policy Report) HTML 다운로드 및 조회
@app.route("/download/policy/<job_id>")
def download_policy(job_id):
    path = os.path.join(
        RESULTS_DIR,
        job_id,
        "policy_report.html"
    )

    if not os.path.exists(path):
        return "Policy report not found", 404

    return send_file(
        path,
        as_attachment=True
    )


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8080
    )
