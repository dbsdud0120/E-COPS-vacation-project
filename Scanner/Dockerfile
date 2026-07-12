# Python 3.11이 설치된 경량 Linux 기반 이미지 사용
FROM python:3.11-slim

# 컨테이너 내부 작업 디렉터리 설정
WORKDIR /app

# 현재 Scanner 폴더의 모든 파일을 컨테이너의 /app으로 복사
COPY . .

# requirements.txt에 정의된 Python 라이브러리 설치
# --no-cache-dir 옵션으로 pip 캐시를 저장하지 않아 이미지 용량 감소
RUN pip install --no-cache-dir -r requirements.txt

# 컨테이너 실행 시 Scanner 프로그램 실행
CMD ["python", "scanner.py"]
