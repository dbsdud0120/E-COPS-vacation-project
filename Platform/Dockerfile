# Python 실행 환경
FROM python:3.11-slim


# 작업 폴더
WORKDIR /app


# Platform 파일 복사
COPY . .


# Flask 설치
RUN pip install --no-cache-dir -r requirements.txt


# 실행 포트
EXPOSE 8080


# Platform 실행
CMD ["python","app.py"]
