import os
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

# 요청 설정
REQUEST_DELAY = 0.5      # 요청 간 딜레이 (초)
REQUEST_TIMEOUT = 8    # 요청 타임아웃 (초)
MAX_RETRIES = 2          # 실패 시 재시도 횟수

# 크롤링 설정
MAX_DEPTH = 2            # 최대 크롤링 깊이
MAX_PAGES = 100          # 최대 수집 페이지 수 (무한 크롤링 방지)

# http_client.py에서 필요                                 
#  
# http_client.py가 REQUEST_DELAY를 RATE_LIMIT_DELAY로 참조
RATE_LIMIT_DELAY = REQUEST_DELAY
 
# 요청 User-Agent
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
 
#  DB 연결 (db/connection.py에서 사용)                     
 
DB_HOST     = os.getenv("DB_HOST",     "localhost")
DB_PORT     = int(os.getenv("DB_PORT", "3306"))
DB_NAME     = os.getenv("DB_NAME",     "vulnerability_scanner")
DB_USER     = os.getenv("DB_USER",     "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "root")

 # 실제 배포 시 환경변수로 교체 권장
                         # ex) os.environ.get("DB_PASSWORD", "")
 # host="localhost",
# port=3306,
# user="root",
# password="teammijung12345*",
# database="vulnerability_scanner"

# ── Groq API 설정 (.env에서 로드) ────────────────────────────────
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL   = os.getenv("GROQ_MODEL",   "llama-3.3-70b-versatile")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"