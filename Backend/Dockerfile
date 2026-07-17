FROM python:3.11-slim

# 컨테이너 내부 작업 폴더
WORKDIR /app

# Backend 폴더 전체 복사
COPY . .

# Python 라이브러리 설치
RUN pip install --no-cache-dir -r requirements.txt

# Flask 실행 포트
EXPOSE 5000

# 컨테이너 실행 시 Flask 실행
CMD ["sh", "-c", "python init_db.py && python app.py"]
