from flask import Blueprint, render_template, request, send_from_directory, session
import os
import pymysql 
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

def get_db():
    return pymysql.connect(
        host=os.getenv("MYSQL_HOST", "localhost"),
        user=os.getenv("MYSQL_USER", "user"),
        password=os.getenv("MYSQL_PASSWORD", "1234"),
        database=os.getenv("MYSQL_DATABASE", "evulnscanner"),
        charset="utf8mb4"
    )


def allowed_file(filename):

    return "." in filename and \
           filename.rsplit(".",1)[1].lower() in ALLOWED_EXTENSIONS


# ==========================
# 정상 파일 업로드
# ==========================

@upload_bp.route("/upload", methods=["GET", "POST"])
def upload():

    if request.method == "POST":

        # 로그인 여부 확인
        if "user_id" not in session:
            return "로그인이 필요합니다.", 401

        file = request.files.get("file")

        if file is None or file.filename == "":
            return "파일을 선택하세요."

        if not allowed_file(file.filename):
            return "허용되지 않는 파일 형식입니다."

        filename = secure_filename(file.filename)

        os.makedirs(SAFE_UPLOAD_FOLDER, exist_ok=True)

        file_path = os.path.join(SAFE_UPLOAD_FOLDER, filename)

        file.save(file_path)

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO files
        (filename, saved_name, file_path, upload_type, user_id)
        VALUES (%s, %s, %s, %s, %s)
        """, (
            file.filename,
            filename,
            file_path,
            "safe",
            session["user_id"]
        ))

        conn.commit()
        cursor.close()
        conn.close()

        return "업로드 성공!"

    return render_template("upload.html")


# ==========================================
# 의도적 취약점 예제: File Upload
# 파일명 및 확장자 검증 없이 업로드
# 실제 서비스에서는 사용하면 안 됨
# ==========================================

@upload_bp.route("/vuln/upload", methods=["GET", "POST"])
def vuln_upload():

    if request.method == "POST":

        # 로그인 여부 확인
        if "user_id" not in session:
            return "로그인이 필요합니다.", 401

        file = request.files.get("file")

        if file is None or file.filename == "":
            return "파일을 선택하세요."

        # 파일명만 안전하게 처리
        # (확장자 검증은 하지 않아 File Upload 취약점은 그대로 유지)
        filename = secure_filename(file.filename)

        os.makedirs(VULN_UPLOAD_FOLDER, exist_ok=True)

        file_path = os.path.join(VULN_UPLOAD_FOLDER, filename)

        file.save(file_path)

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO files
        (filename, saved_name, file_path, upload_type, user_id)
        VALUES (%s, %s, %s, %s, %s)
        """, (
            file.filename,
            filename,
            file_path,
            "vuln",
            session["user_id"]
        ))

        conn.commit()
        cursor.close()
        conn.close()

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