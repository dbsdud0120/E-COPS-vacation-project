from flask import Flask, render_template, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users(username,password) VALUES (?,?)",
            (username, password)
        )

        conn.commit()
        conn.close()

        return "회원가입 성공!"

    return render_template("signup.html")


@app.route("/users")
def users():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users")

    users = cursor.fetchall()

    conn.close()

    return str(users)


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        )

        user = cursor.fetchone()

        conn.close()

        if user:
            return "로그인 성공!"
        else:
            return "로그인 실패!"

    return render_template("login.html")


@app.route("/posts", methods=["GET", "POST"])
def posts():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    if request.method == "POST":

        title = request.form["title"]
        content = request.form["content"]
        writer = request.form["writer"]

        cursor.execute(
            "INSERT INTO posts(title, content, writer) VALUES (?, ?, ?)",
            (title, content, writer)
        )

        conn.commit()

    keyword = request.args.get("keyword", "")

    if keyword:
        cursor.execute(
            "SELECT * FROM posts WHERE title LIKE ? ORDER BY id DESC",
            (f"%{keyword}%",)
        )
    else:
        cursor.execute(
            "SELECT * FROM posts ORDER BY id DESC"
        )

    posts = cursor.fetchall()

    conn.close()

    return render_template(
        "posts.html",
        posts=posts,
        keyword=keyword
    )


@app.route("/api/posts")
def api_posts():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM posts")

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


@app.route("/api/posts/<int:post_id>")
def api_post(post_id):

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM posts WHERE id=?",
        (post_id,)
    )

    post = cursor.fetchone()

    conn.close()

    if post is None:
        return jsonify({"error": "게시글 없음"}), 404

    return jsonify({

        "id": post[0],
        "title": post[1],
        "content": post[2],
        "writer": post[3]

    })


@app.route("/api/vuln/login", methods=["POST"])
def vuln_login():

    username = request.form.get("username")
    password = request.form.get("password")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    print(query)

    cursor.execute(query)

    user = cursor.fetchone()

    conn.close()

    if user:
        return jsonify({
            "success": True,
            "message": "로그인 성공"
        })

    else:
        return jsonify({
            "success": False,
            "message": "로그인 실패"
        })


@app.route("/vuln/comment")
def comment():

    text = request.args.get("text", "")

    return f"""
    <h2>댓글</h2>
    <p>{text}</p>
    """


if __name__ == "__main__":
    app.run(debug=True)