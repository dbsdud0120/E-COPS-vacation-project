from flask import Flask, request, jsonify
import subprocess
import os

app = Flask(__name__)


@app.route("/report", methods=["POST"])
def report():

    data = request.get_json()

    json_path = data["json_path"]

    report_prefix = os.path.join(
        os.path.dirname(json_path),
        "report"
    )

    subprocess.run(
        [
            "python",
            "report_generator.py",
            json_path,
            report_prefix
        ],
        cwd="/app",
        check=True
    )

    return jsonify({
        "html": report_prefix + ".html",
        "pdf": report_prefix + ".pdf"
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5002
    )
