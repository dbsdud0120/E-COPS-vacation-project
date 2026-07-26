import os
import pymysql
from werkzeug.security import generate_password_hash

conn = pymysql.connect(
    host=os.getenv("MYSQL_HOST", "localhost"),
    user=os.getenv("MYSQL_USER", "user"),
    password=os.getenv("MYSQL_PASSWORD", "1234"),
    database=os.getenv("MYSQL_DATABASE", "evulnscanner"),
    charset="utf8mb4"
)

cursor = conn.cursor()

# ==========================
# users
# ==========================
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
)
""")

# ==========================
# posts
# ==========================
cursor.execute("""
CREATE TABLE IF NOT EXISTS posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    writer VARCHAR(50) NOT NULL
)
""")

# ==========================
# files
# ==========================
cursor.execute("""
CREATE TABLE IF NOT EXISTS files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    saved_name VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    upload_type ENUM('safe', 'vuln') NOT NULL,
    user_id INT NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
""")

# ==========================
# 테스트 계정
# ==========================
test_users = [
    ("admin", "12345678"),
    ("test1", "12345678"),
    ("user1", "12345678")
]

for username, password in test_users:
    cursor.execute(
        """
        INSERT IGNORE INTO users(username, password)
        VALUES(%s, %s)
        """,
        (username, generate_password_hash(password))
    )

# ==========================
# 테스트 게시글
# ==========================
test_posts = [
    ("공지사항", "EVulnScanner 테스트용 공지입니다.", "admin"),
    ("첫 번째 게시글", "게시판 기능 테스트용 게시글입니다.", "admin"),
    ("XSS 테스트", "<script>alert('xss')</script>", "test1")
]

for title, content, writer in test_posts:
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM posts
        WHERE title = %s AND writer = %s
        """,
        (title, writer)
    )

    if cursor.fetchone()[0] == 0:
        cursor.execute(
            """
            INSERT INTO posts(title, content, writer)
            VALUES(%s, %s, %s)
            """,
            (title, content, writer)
        )

conn.commit()

cursor.close()
conn.close()

print("데이터베이스 초기화 및 테스트 데이터 생성 완료!")