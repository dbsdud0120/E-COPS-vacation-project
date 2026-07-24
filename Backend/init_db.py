import os
import time
import pymysql

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

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    writer VARCHAR(50) NOT NULL
)
""")

conn.commit()

cursor.close()
conn.close()

print("데이터베이스 생성 완료!")