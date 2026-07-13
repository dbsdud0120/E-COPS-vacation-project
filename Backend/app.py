from flask import Flask, render_template, request, jsonify, session
import os
import re
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
from upload import upload_bp


app = Flask(__name__)
app.register_blueprint(upload_bp)

# 세션 암호화 키
app.secret_key = "evulnscanner-secret-key"


def get_db():
    conn = pymysql.connect(
        host=os.getenv("MYSQL_HOST", "localhost"),
        user=os.getenv("MYSQL_USER", "user"),
        password=os.getenv("MYSQL_PASSWORD", "1234"),
        database=os.getenv("MYSQL_DATABASE", "evulnscanner"),
        charset="utf8mb4"
    )
    return conn


@app.route("/")
def home():

    return render_template("index.html")



# 회원가입
# 회원가입
@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 입력값 검증
        if not username or not password:
            return "아이디와 비밀번호를 입력하세요."

        # 아이디 길이 제한
        if len(username) < 4 or len(username) > 20:
            return "아이디는 4~20자만 가능합니다."

        # 비밀번호 길이 제한
        if len(password) < 8 or len(password) > 20:
            return "비밀번호는 8~20자만 가능합니다."

        # 아이디 특수문자 제한
        if not re.fullmatch(r"[A-Za-z0-9_]+", username):
            return "아이디는 영문, 숫자, _(언더바)만 사용할 수 있습니다."

        # 비밀번호 해시
        hashed_password = generate_password_hash(password)

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO users(username,password)
            VALUES(%s,%s)
            """,
            (username, hashed_password)
        )

        conn.commit()
        conn.close()

        return "회원가입 성공!"

    return render_template("signup.html")




# 사용자 조회 (인증 테스트)
@app.route("/users")
def users():

    if "username" not in session:
        return jsonify({
            "error": "로그인이 필요합니다."
        }), 401

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, username FROM users"
    )

    users = cursor.fetchall()

    conn.close()

    result = []

    for user in users:
        result.append({
            "id": user[0],
            "username": user[1]
        })

    return jsonify(result)




#로그인
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 입력값 검증
        if not username or not password:
            return "아이디와 비밀번호를 모두 입력하세요."

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT * FROM users
            WHERE username=%s
            """,
            (username,)
        )

        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[2], password):

            # 로그인 성공 → 세션 저장
            session["username"] = username

            return "로그인 성공!"

        return "아이디 또는 비밀번호가 올바르지 않습니다."

    return render_template("login.html")

# ==========================================
# 의도적 취약점 예제: Broken Authentication
# 비밀번호 검증 없이 사용자 존재 여부만 확인
# 실제 서비스에서는 사용하면 안 됨
# ==========================================

@app.route("/vuln/broken-auth", methods=["POST"])
def vuln_broken_auth():

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return jsonify({
            "success": False,
            "message": "아이디와 비밀번호를 입력하세요."
        }), 400

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM users
        WHERE username=%s
        """,
        (username,)
    )

    user = cursor.fetchone()

    conn.close()

    # -----------------------------
    # 의도적 취약점 
    # 비밀번호를 검증하지 않고
    # 사용자 존재 여부만 확인
    # -----------------------------
    if user:

        session["username"] = username

        return jsonify({
            "success": True,
            "message": "로그인 성공 (Broken Authentication)"
        })

    return jsonify({
        "success": False,
        "message": "존재하지 않는 사용자입니다."
    }), 404

# 로그아웃
@app.route("/logout")
def logout():

    session.clear()

    return """
    <script>
    alert("로그아웃되었습니다.");
    location.href="/";
    </script>
    """




@app.route("/posts", methods=["GET","POST"])
def posts():


    conn = get_db()
    cursor = conn.cursor()



    if request.method == "POST":


        if "username" not in session:
            conn.close()
            return "로그인이 필요합니다."

        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()

        # 작성자는 로그인한 사용자로 고정
        writer = session["username"]


        # 입력값 검증
        if not title or not content or not writer:

            conn.close()
            return "모든 값을 입력하세요."


        # 제목 길이 제한
        if len(title) > 100:

            conn.close()
            return "제목은 100자 이하만 가능합니다."


        cursor.execute(

            """
            INSERT INTO posts(title,content,writer)
            VALUES(%s,%s,%s)
            """,

            (title,content,writer)

        )


        conn.commit()



    keyword = request.args.get("keyword","").strip()



    if keyword:


        cursor.execute(

            """
            SELECT * FROM posts
            WHERE title LIKE %s
            ORDER BY id DESC
            """,

            (f"%{keyword}%",)

        )


    else:


        cursor.execute(

            """
            SELECT * FROM posts
            ORDER BY id DESC
            """

        )



    posts = cursor.fetchall()


    conn.close()



    return render_template(

        "posts.html",

        posts=posts,

        keyword=keyword

    )

# ==========================================
# 의도적 취약점 예제: Stored XSS
# 게시글 내용을 escaping 없이 출력
# ==========================================

@app.route("/vuln/posts")
def vuln_posts():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM posts
        ORDER BY id DESC
        """
    )

    posts = cursor.fetchall()

    conn.close()

    return render_template(
        "vuln_posts.html",
        posts=posts
    )






# 게시글 API 전체 조회 + 검색
@app.route("/api/posts")
def api_posts():

    keyword = request.args.get("keyword", "")

    conn = get_db()
    cursor = conn.cursor()


    if keyword:

        cursor.execute(
            """
            SELECT * FROM posts
            WHERE title LIKE %s
            ORDER BY id DESC
            """,
            (f"%{keyword}%",)
        )

    else:

        cursor.execute(
            """
            SELECT * FROM posts
            ORDER BY id DESC
            """
        )


    posts = cursor.fetchall()


    conn.close()


    result = []


    for post in posts:

        result.append({

            "id": post[0],
            "title": post[1],
            "content": post[2],
            "writer": post[3]

        })


    return jsonify(result)






# 게시글 API 단일 조회
@app.route("/api/posts/<int:post_id>")
def api_post(post_id):


    conn=get_db()
    cursor=conn.cursor()


    cursor.execute(

        """
        SELECT * FROM posts
        WHERE id=%s
        """,

        (post_id,)

    )


    post=cursor.fetchone()


    conn.close()



    if post is None:


        return jsonify(
            {
                "error":"게시글 없음"
            }
        ),404



    return jsonify({

        "id":post[0],
        "title":post[1],
        "content":post[2],
        "writer":post[3]

    })

# 게시글 수정
@app.route("/posts/edit/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):

    conn = get_db()
    cursor = conn.cursor()

    # 게시글 조회
    cursor.execute(
        """
        SELECT * FROM posts
        WHERE id=%s
        """,
        (post_id,)
    )

    post = cursor.fetchone()

    if post is None:
        conn.close()
        return "게시글이 존재하지 않습니다."

    # 로그인 확인
    if "username" not in session:
        conn.close()
        return "로그인이 필요합니다."

    # 작성자 확인
    if post[3] != session["username"]:
        conn.close()
        return "작성자만 수정할 수 있습니다."

    if request.method == "POST":

        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()

        # 제목 검증
        if not title:
            conn.close()
            return "제목을 입력하세요."

        if len(title) > 100:
            conn.close()
            return "제목은 100자 이하만 가능합니다."

        # 내용 검증
        if not content:
            conn.close()
            return "내용을 입력하세요."

        cursor.execute(
            """
            UPDATE posts
            SET title=%s,
                content=%s
            WHERE id=%s
            """,
            (title, content, post_id)
        )

        conn.commit()
        conn.close()

        return """
        <script>
        alert("수정 완료");
        location.href="/posts";
        </script>
        """

    conn.close()

    return render_template(
        "edit_post.html",
        post=post
    )

# 게시글 삭제
@app.route("/posts/delete/<int:post_id>")
def delete_post(post_id):

    conn = get_db()
    cursor = conn.cursor()

    # 게시글 조회
    cursor.execute(
        """
        SELECT * FROM posts
        WHERE id=%s
        """,
        (post_id,)
    )

    post = cursor.fetchone()

    if post is None:
        conn.close()
        return "게시글이 존재하지 않습니다."

    # 로그인 확인
    if "username" not in session:
        conn.close()
        return "로그인이 필요합니다."

    # 작성자 확인
    if post[3] != session["username"]:
        conn.close()
        return "작성자만 삭제할 수 있습니다."

    # 삭제
    cursor.execute(
        """
        DELETE FROM posts
        WHERE id=%s
        """,
        (post_id,)
    )

    conn.commit()
    conn.close()

    return """
    <script>
    alert("삭제 완료");
    location.href="/posts";
    </script>
    """



# ==========================================
# 의도적 취약점 예제: IDOR (게시글 수정)
# 권한 확인 없이 게시글 수정 가능
# ==========================================

@app.route("/vuln/posts/edit/<int:post_id>", methods=["GET", "POST"])
def vuln_edit_post(post_id):

    conn = get_db()
    cursor = conn.cursor()

    if request.method == "POST":

        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()

        cursor.execute(
            """
            UPDATE posts
            SET title=%s, content=%s
            WHERE id=%s
            """,
            (title, content, post_id)
        )

        conn.commit()
        conn.close()

        return """
        <script>
        alert("취약 수정 완료");
        location.href="/posts";
        </script>
        """

    cursor.execute(
        """
        SELECT * FROM posts
        WHERE id=%s
        """,
        (post_id,)
    )

    post = cursor.fetchone()

    conn.close()

    if post is None:
        return "게시글이 존재하지 않습니다."

    return render_template(
        "edit_post.html",
        post=post
    )


# ==========================================
# 의도적 취약점 예제: IDOR (게시글 삭제)
# 권한 확인 없이 게시글 삭제 가능
# ==========================================

@app.route("/vuln/posts/delete/<int:post_id>")
def vuln_delete_post(post_id):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        DELETE FROM posts
        WHERE id=%s
        """,
        (post_id,)
    )

    conn.commit()
    conn.close()

    return """
    <script>
    alert("취약 삭제 완료");
    location.href="/posts";
    </script>
    """



# ==========================================
# 의도적 취약점 예제: SQL Injection
# 사용자 입력값(username, password)을 검증 없이
# SQL 쿼리에 직접 삽입하는 취약한 코드
# 실제 서비스에서는 사용하면 안 됨
# ==========================================


@app.route("/vuln/login", methods=["POST"])
def vuln_login():


    username=request.form.get("username")
    password=request.form.get("password")


    conn=get_db()
    cursor=conn.cursor()


    # 의도적 취약점 발생 부분
# Prepared Statement를 사용하지 않고
# 문자열 조합으로 SQL Query 생성
    query=f"""
    SELECT * FROM users
    WHERE username='{username}'
    AND password='{password}'
    """


    print(query)


    cursor.execute(query)


    user=cursor.fetchone()


    conn.close()



    if user:

        return jsonify({

            "success":True,
            "message":"로그인 성공"

        })


    return jsonify({

        "success":False,
        "message":"로그인 실패"

    })






# ==========================================
# 의도적 취약점 예제: Stored XSS
# 사용자 입력값을 HTML escaping 없이 출력하는 취약한 코드
# 실제 서비스에서는 입력값 검증 및 escaping 필요
# ==========================================
@app.route("/vuln/comment")
def comment():


    text=request.args.get("text","")


    return f"""

    <h2>댓글</h2>

    <p>{text}</p>

    """

# ==========================================
# 의도적 취약점 예제: Directory Traversal
# 사용자 입력을 파일 경로 검증 없이 사용
# 실제 서비스에서는 사용하면 안 됨
# ==========================================

@app.route("/vuln/download")
def vuln_download():

    filename = request.args.get("file")

    if not filename:
        return "파일명을 입력하세요."

    try:

        with open(filename, "r", encoding="utf-8") as f:
            return f.read()

    except Exception as e:
        return str(e)




if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

    