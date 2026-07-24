from flask import Flask, request, jsonify
import subprocess
import uuid
import os

app = Flask(__name__)

RESULTS_DIR = "/app/results"


@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json()

    url = data["url"]

    # Platform이 job_id를 함께 넘겨주면 그 값을 그대로 사용해서
    # Platform/Scanner/Report가 같은 폴더를 바라보게 한다.
    # job_id가 없으면(=Scanner를 단독으로 테스트할 때) 새로 발급한다.
    job_id = data.get("job_id") or str(uuid.uuid4())

    result_dir = os.path.join(
        RESULTS_DIR,
        job_id
    )

    os.makedirs(result_dir, exist_ok=True)

    env = os.environ.copy()
    env["RESULTS_DIR"] = result_dir

    subprocess.run(
        [
            "python",
            "scanner.py",
            url
        ],
        cwd="/app",
        env=env,
        check=True
    )

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
