FROM python:3.11-slim

# 컨테이너 내부 작업 폴더
WORKDIR /app

# Report 폴더 전체 복사
COPY . .

# 필요한 Python 라이브러리 설치
RUN pip install --no-cache-dir \
    Jinja2 \
    WeasyPrint \
    Markdown

# 보고서 생성 실행
CMD ["python", "report_generator.py"]
