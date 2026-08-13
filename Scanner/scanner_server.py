from flask import Flask, request, jsonify, send_from_directory
from flask_swagger_ui import get_swaggerui_blueprint
import subprocess
import uuid
import os
import sys

app = Flask(__name__)

RESULTS_DIR = "/app/results"

SWAGGER_URL = "/docs"
API_URL = "/swagger.yaml"

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        "app_name": "Scanner API Documentation"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "요청 본문에 'url' 필드가 필요합니다."}), 400

    url = data["url"]
    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "'url'은 비어있지 않은 문자열이어야 합니다."}), 400
    url = url.strip()

    job_id = data.get("job_id") or str(uuid.uuid4())
    result_dir = os.path.join(RESULTS_DIR, job_id)
    os.makedirs(result_dir, exist_ok=True)

    env = os.environ.copy()
    env["RESULTS_DIR"] = result_dir

    log_path = os.path.join(result_dir, "scan.log")

    # 실시간 로그 기록을 위해 Popen + 라인 단위 읽기로 변경
    # -u 옵션: 파이썬 출력 버퍼링 비활성화 (즉시 flush)
    with open(log_path, "w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            [
                sys.executable, "-u", "scanner.py",
                url,
                "--swagger",
                f"{url.rstrip('/')}/swagger.yaml"
            ],
            cwd="/app",
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in process.stdout:
            log_file.write(line)
            log_file.flush()

        process.wait()

    if process.returncode != 0:
        return jsonify({"error": "scan failed"}), 500

    files = [
        f for f in os.listdir(result_dir)
        if f.endswith(".json")
    ]

    if len(files) == 0:
        return jsonify({"error": "scan failed"}), 500

    return jsonify({
        "job_id": job_id,
        "json_path": os.path.join(result_dir, files[0])
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5001
    )
