import os
import time
import pymysql
from werkzeug.security import generate_password_hash

# MySQL 컨테이너가 완전히 요청을 받을 준비가 되기까지 시간이 걸릴 수 있는데,
# 기존에는 한 번 연결을 시도해서 실패하면 그대로 죽어버렸다. entrypoint.sh는 이 실패를
# 무시하고 app.py를 그냥 실행해버려서, "테이블이 없다"는 에러가 반복해서 나는 문제가 있었음.
# -> MySQL이 준비될 때까지 몇 초 간격으로 재시도한다.
MAX_RETRIES = 15
RETRY_DELAY_SECONDS = 2


def connect_with_retry():
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return pymysql.connect(
                host=os.getenv("MYSQL_HOST", "localhost"),
                user=os.getenv("MYSQL_USER", "user"),
                password=os.getenv("MYSQL_PASSWORD", "1234"),
                database=os.getenv("MYSQL_DATABASE", "evulnscanner"),
                charset="utf8mb4"
            )
        except pymysql.err.OperationalError as e:
            last_error = e
            print(f"[init_db] MySQL 연결 대기 중... ({attempt}/{MAX_RETRIES}) {e}")
            time.sleep(RETRY_DELAY_SECONDS)
    raise RuntimeError(f"[init_db] MySQL에 연결하지 못했습니다: {last_error}")


conn = connect_with_retry()

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