FROM python:3.11-slim

# WeasyPrint에 필요한 시스템 라이브러리 설치

RUN apt-get update && apt-get install -y \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# 컨테이너 내부 작업 폴더
WORKDIR /app

# Report 폴더 전체 복사
COPY . .

# 필요한 Python 라이브러리 설치
RUN pip install --no-cache-dir -r requirements.txt

# 보고서 생성 실행
CMD ["python", "report_server.py"]
