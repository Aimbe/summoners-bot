from flask import Flask, request, jsonify, redirect, session
import requests
import os
import json

app = Flask(__name__)

# --- 환경 변수 로드 및 검증 ---
# API 설정
KAKAO_API_URL = os.getenv("KAKAO_API_URL", "https://kapi.kakao.com")

# 카카오 로그인 설정
KAKAO_REST_API_KEY = os.getenv("KAKAO_REST_API_KEY")
REDIRECT_URI = os.getenv("REDIRECT_URI")

# 챗봇 메시지 발송용 관리자 키
KAKAO_BOT_ADMIN_KEY = os.getenv("KAKAO_BOT_ADMIN_KEY")

# Flask 세션 키
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")

# 필수 환경 변수 검증
if not KAKAO_REST_API_KEY:
    raise ValueError("환경 변수 'KAKAO_REST_API_KEY'가 설정되지 않았습니다.")
if not REDIRECT_URI:
    raise ValueError("환경 변수 'REDIRECT_URI'가 설정되지 않았습니다.")
if not FLASK_SECRET_KEY:
    raise ValueError("환경 변수 'FLASK_SECRET_KEY'가 설정되지 않았습니다.")
# KAKAO_BOT_ADMIN_KEY 는 메시지 발송 시점에 확인하므로 여기서는 경고만 (필요 시 아래 주석 해제)
# if not KAKAO_BOT_ADMIN_KEY:
#     raise ValueError("환경 변수 'KAKAO_BOT_ADMIN_KEY'가 설정되지 않았습니다.")

# Flask 앱 시크릿 키 설정
app.secret_key = FLASK_SECRET_KEY

# 데이터 로드
# 실제 데이터는 추후 사용자가 제공할 예정
MONSTERS_DATA = {
    # 몬스터명 : [방덱1, 방덱2, ...]
    "물신수": ["물신수,풍그림자,불닭", "물신수,빛용병왕,불신수"],
    "풍그림자": ["물신수,풍그림자,불닭"],
    "불닭": ["물신수,풍그림자,불닭"],
    "물마도": ["물마도,풍도깨비,빛암"],
    "풍도깨비": ["물마도,풍도깨비,빛암", "물,풍도깨비,빛암"],
    "빛암": ["물마도,풍도깨비,빛암", "물,풍도깨비,빛암", "물신수,빛용병왕,불신수"],
    "빛용병왕": ["물신수,빛용병왕,불신수"],
    "불신수": ["물신수,빛용병왕,불신수"]
}

# 방덱 데이터
DECK_DATA = {
    "물신수,풍그림자,불닭": {
        "offense": "물쿠키,물발,물인어",
        "advantages": "상대 풍속성 딜러가 없을시 기용하기 매우좋음. 물신수 풍그림자 불닭에 매우강함.",
        "disadvantages": "물인어가 무조건 들어가다보니 물호울로 대체 시 안정성 떨어짐.",
        "usage": "물패링이 기절 걸릴 확률 높음, 물인어 실드로 기절 풀어줄 것. 불받피 아티 권장.",
        "suitable_defenses": ["물신수,풍그림자,불닭", "불스나,물발,풍깨비", "불사전,물용병왕,풍드루"]
    },
    "물마도,풍도깨비,빛암": {
        "offense": "풍도깨비,풍오공,풍푸딩공주",
        "advantages": "불극딜러만 없다면 어떤상황에서 꺼내도 엄청 좋은덱. 조작난이도 가장 낮음.",
        "disadvantages": "불이프 방덱에는 절대 들어가지 말것!",
        "usage": "풍도깨비를 살리는 방향. 상대 물속성부터 잡거나, 약한 빛암 먼저 타겟. 풍오공은 오른쪽 아티(체력 낮은 몬스터 주는 피해량 증가) 권장.",
        "suitable_defenses": ["물마도,풍도깨비,빛암", "물신수,빛용병왕,불신수", "물,풍도깨비,빛암"]
    },
    "물신수,빛용병왕,불신수": {
        "offense": "물,물,물",
        "advantages": "물 속성 덱으로 강력한 불 속성 방어덱에 효과적",
        "disadvantages": "풍 속성 공격에 취약함",
        "usage": "물 속성 딜러로 불신수부터 집중 공략",
        "suitable_defenses": ["물신수,빛용병왕,불신수", "불,불,불"]
    },
    "물,풍도깨비,빛암": {
        "offense": "물,물,물",
        "advantages": "물 속성 덱으로 풍도깨비와 빛암 견제 가능",
        "disadvantages": "물 몬스터가 약하면 어려움",
        "usage": "물 속성 딜러로 빛암부터 처리",
        "suitable_defenses": ["물,풍도깨비,빛암", "불,불,불"]
    }
}

def normalize(text):
    """텍스트 정규화: 공백 제거 및 소문자화"""
    return text.replace(" ", "").lower()

def find_decks_with_monster(monster_name):
    """몬스터 이름으로 방덱 찾기"""
    normalized_name = normalize(monster_name)
    found_decks = MONSTERS_DATA.get(normalized_name, [])
    return found_decks

def get_offense_recommendations(defense_deck):
    """방덱에 대한 공덱 추천 정보 찾기"""
    deck_info = DECK_DATA.get(defense_deck)
    if not deck_info:
        return None
    return deck_info

@app.route("/", methods=["GET"])
def home():
    """기본 홈페이지"""
    return "서머너즈워 점령전 공덱 추천 봇이 실행 중입니다."

@app.route("/login/kakao")
def kakao_login():
    """카카오 로그인 페이지로 리다이렉트합니다."""
    kakao_auth_url = (
        f"https://kauth.kakao.com/oauth/authorize?response_type=code"
        f"&client_id={KAKAO_REST_API_KEY}"
        f"&redirect_uri={REDIRECT_URI}"
    )
    return redirect(kakao_auth_url)

@app.route("/auth/callback", methods=["GET"])
def auth_callback():
    """카카오 로그인 후 콜백을 처리하고 액세스 토큰을 발급받습니다."""
    code = request.args.get('code')
    if not code:
        return "인증 코드를 받지 못했습니다.", 400

    token_url = "https://kauth.kakao.com/oauth/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded;charset=utf-8"}
    data = {
        "grant_type": "authorization_code",
        "client_id": KAKAO_REST_API_KEY,
        "redirect_uri": REDIRECT_URI,
        "code": code,
        # 클라이언트 시크릿을 사용하는 경우 아래 주석 해제 및 값 설정 필요
        # "client_secret": "YOUR_CLIENT_SECRET"
    }

    try:
        token_response = requests.post(token_url, headers=headers, data=data)
        token_response.raise_for_status() # HTTP 오류 발생 시 예외 발생
        token_json = token_response.json()

        access_token = token_json.get("access_token")
        refresh_token = token_json.get("refresh_token") # 필요시 저장

        # 세션에 액세스 토큰 저장 (간단한 예시)
        session['kakao_access_token'] = access_token
        if refresh_token:
            session['kakao_refresh_token'] = refresh_token # 리프레시 토큰도 저장

        # 로그인 성공 후 리다이렉트 또는 메시지 표시
        # 예시: 사용자 정보 요청 후 환영 메시지
        user_info = get_kakao_user_info(access_token)
        if user_info:
             nickname = user_info.get('properties', {}).get('nickname', '사용자')
             return f"{nickname}님, 카카오 로그인 성공! <a href='/'>홈으로</a>"
        else:
             return f"카카오 로그인 성공! (사용자 정보 가져오기 실패) 액세스 토큰: {access_token} <a href='/'>홈으로</a>"


    except requests.exceptions.RequestException as e:
        print(f"액세스 토큰 요청 실패: {e}")
        print(f"응답 내용: {token_response.text if 'token_response' in locals() else 'N/A'}")
        return f"액세스 토큰 요청 실패: {e}", 500
    except Exception as e:
        print(f"콜백 처리 중 오류 발생: {e}")
        return f"오류 발생: {e}", 500

def get_kakao_user_info(access_token):
    """액세스 토큰을 사용하여 카카오 사용자 정보를 요청합니다."""
    user_info_url = "https://kapi.kakao.com/v2/user/me"
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        user_info_response = requests.get(user_info_url, headers=headers)
        user_info_response.raise_for_status()
        return user_info_response.json()
    except requests.exceptions.RequestException as e:
        print(f"사용자 정보 요청 실패: {e}")
        return None

@app.route("/webhook", methods=["POST"])
def webhook():
    """카카오톡 웹훅 처리"""
    # 요청 데이터 파싱
    data = request.get_json()
    
    # 카카오톡 오픈채팅방 요청 검증 및 처리
    try:
        # 카카오톡은 type과 content 형태로 전송
        if 'type' in data and data['type'] == 'message':
            user_msg = data.get('content', '')
            room_id = data.get('room', {}).get('id', '')
            user_id = data.get('user', {}).get('id', '')
            
            # !몬스터 명령어 처리
            if user_msg.startswith("!몬스터"):
                monster_name = user_msg.replace("!몬스터", "").strip()
                if not monster_name:
                    return jsonify({"message": "몬스터 이름을 입력해주세요. 예: !몬스터 물신수"})
                
                defense_decks = find_decks_with_monster(monster_name)
                
                if not defense_decks:
                    return jsonify({
                        "message": f"'{monster_name}' 몬스터가 포함된 방덱을 찾을 수 없습니다."
                    })
                
                # 응답 메시지 생성
                response = f"'{monster_name}' 몬스터가 포함된 방덱 및 추천 공덱:\n\n"
                
                for deck in defense_decks:
                    offense_info = get_offense_recommendations(deck)
                    if offense_info:
                        response += f"방덱: {deck}\n"
                        response += f"추천 공덱: {offense_info['offense']}\n"
                        response += f"장점: {offense_info['advantages']}\n"
                        response += f"단점: {offense_info['disadvantages']}\n"
                        response += f"사용법: {offense_info['usage']}\n\n"
                
                return jsonify({"message": response})
            
            # !공덱 명령어 처리 (기존 기능 유지)
            elif user_msg.startswith("!공덱"):
                defense_deck = normalize(user_msg.replace("!공덱", "").strip())
                if not defense_deck:
                    return jsonify({"message": "방덱을 입력해주세요. 예: !공덱 물신수,풍그림자,불닭"})
                
                deck_info = get_offense_recommendations(defense_deck)
                
                if deck_info:
                    response = (
                        f"방덱: {defense_deck}\n"
                        f"추천 공덱: {deck_info['offense']}\n"
                        f"장점: {deck_info['advantages']}\n"
                        f"단점: {deck_info['disadvantages']}\n"
                        f"사용법: {deck_info['usage']}"
                    )
                else:
                    response = f"'{defense_deck}' 방덱에 맞는 공덱을 찾을 수 없습니다."
                
                return jsonify({"message": response})
            
            # !도움말 명령어 처리
            elif user_msg == "!도움말":
                help_text = (
                    "서머너즈워 점령전 공덱 추천 봇 사용법:\n\n"
                    "1. !몬스터 [몬스터명] - 해당 몬스터가 포함된 방덱과 추천 공덱 확인\n"
                    "예: !몬스터 물신수\n\n"
                    "2. !공덱 [방덱구성] - 해당 방덱에 대한 추천 공덱 확인\n"
                    "예: !공덱 물신수,풍그림자,불닭\n\n"
                    "3. !도움말 - 사용 방법 확인"
                )
                return jsonify({"message": help_text})
        
        # 카카오톡 서버 검증 응답
        return jsonify({"message": "success"})
    
    except Exception as e:
        print(f"오류 발생: {e}")
        return jsonify({"message": "오류가 발생했습니다. 다시 시도해주세요."})

# 데이터 로드 함수 (향후 파일에서 데이터 로드 시 사용)
def load_data_from_file(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            return json.load(file)
    except Exception as e:
        print(f"데이터 파일 로드 실패: {e}")
        return {}

# 앱 실행 설정
if __name__ == "__main__":
    # 기본 포트 설정 (환경 변수 PORT가 없으면 8080 사용)
    port = int(os.environ.get("PORT", 8080))
    # 모든 인터페이스에서 접속 허용, 디버그 모드 비활성화
    app.run(host="0.0.0.0", port=port, debug=False)