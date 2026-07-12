from flask import Blueprint, render_template, request, send_from_directory
import os
from werkzeug.utils import secure_filename

upload_bp = Blueprint("upload", __name__)

BASE_UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")

SAFE_UPLOAD_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "safe")
VULN_UPLOAD_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "vuln")

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

        os.makedirs(SAFE_UPLOAD_FOLDER, exist_ok=True)

        file.save(os.path.join(SAFE_UPLOAD_FOLDER, filename))

        return "업로드 성공!"

    return render_template("upload.html")


# ==========================================
# 의도적 취약점 예제: File Upload
# 파일명 및 확장자 검증 없이 업로드
# 실제 서비스에서는 사용하면 안 됨
# ==========================================

@upload_bp.route("/vuln/upload", methods=["GET","POST"])
def vuln_upload():

    if request.method == "POST":

        file = request.files.get("file")

        if file is None or file.filename == "":
            return "파일을 선택하세요."

        os.makedirs(VULN_UPLOAD_FOLDER, exist_ok=True)

        file.save(os.path.join(VULN_UPLOAD_FOLDER, file.filename))

        return "취약 업로드 성공!"

    return render_template("upload.html")


# ==========================
# 업로드 파일 조회
# ==========================


@upload_bp.route("/uploads/safe/<path:filename>")
def uploaded_safe_file(filename):
    return send_from_directory(SAFE_UPLOAD_FOLDER, filename)


@upload_bp.route("/uploads/vuln/<path:filename>")
def uploaded_vuln_file(filename):
    return send_from_directory(VULN_UPLOAD_FOLDER, filename)