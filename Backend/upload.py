from flask import Blueprint, render_template, request
import os
from werkzeug.utils import secure_filename

upload_bp = Blueprint("upload", __name__)

UPLOAD_FOLDER = "uploads"

ALLOWED_EXTENSIONS = {
    "txt",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "pdf"
}


def allowed_file(filename):

    return "." in filename and \
           filename.rsplit(".",1)[1].lower() in ALLOWED_EXTENSIONS


# ==========================
# 정상 파일 업로드
# ==========================

@upload_bp.route("/upload", methods=["GET","POST"])
def upload():

    if request.method == "POST":

        file = request.files.get("file")

        if file is None or file.filename == "":
            return "파일을 선택하세요."

        if not allowed_file(file.filename):
            return "허용되지 않는 파일 형식입니다."

        filename = secure_filename(file.filename)

        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        file.save(os.path.join(UPLOAD_FOLDER, filename))

        return "업로드 성공!"

    return render_template("upload.html")


# ==========================
# 취약 파일 업로드
# ==========================

@upload_bp.route("/vuln/upload", methods=["GET","POST"])
def vuln_upload():

    if request.method == "POST":

        file = request.files.get("file")

        if file is None or file.filename == "":
            return "파일을 선택하세요."

        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        file.save(os.path.join(UPLOAD_FOLDER, file.filename))

        return "취약 업로드 성공!"

    return render_template("upload.html")