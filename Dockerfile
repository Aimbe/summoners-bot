FROM python:3.9-slim

# 작업 디렉토리 설정
WORKDIR /app

# 필요한 파일 복사
COPY requirements.txt .

# 의존성 설치
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 코드 복사
COPY . .

# 포트 설정 (Qoddi는 PORT 환경변수를 제공)
ENV PORT=8080
EXPOSE $PORT

# 애플리케이션 실행
CMD gunicorn --workers=2 --bind=0.0.0.0:$PORT app:app