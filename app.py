from flask import Flask, request, jsonify, redirect, session
import requests
import os

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

# 공덱 데이터 (샘플 2개, 나머지 추가 가능)
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

}

def normalize(text):
    return text.replace(" ", "").lower()

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
    data = request.get_json()
    user_msg = data.get("message", {}).get("text", "")
    chat_id = data.get("chat_id")

    if user_msg.startswith("!공덱"):
        defense_deck = normalize(user_msg.replace("!공덱", "").strip())
        deck_info = DECK_DATA.get(defense_deck)
        if deck_info:
            reply = (
                f"추천 공덱: {deck_info['offense']}\n"
                f"장점: {deck_info['advantages']}\n"
                f"단점: {deck_info['disadvantages']}\n"
                f"사용법: {deck_info['usage']}"
            )
        else:
            reply = "해당 방덱에 맞는 공덱을 찾을 수 없습니다."
        send_message(chat_id, reply)
        return jsonify({"status": "ok"})
    return jsonify({"status": "ignored"})

def send_message(chat_id, text):
    """카카오톡 메시지를 발송합니다. (챗봇 API용 토큰 사용 필요)"""
    # 중요: 메시지 발송에는 별도의 어드민 키 또는 서비스 앱 토큰이 필요할 수 있습니다.
    # 로그인 통해 얻은 사용자 토큰으로 메시지를 보낼 수 있는지 확인 필요.
    # 일반적으로는 카카오 디벨로퍼스의 어드민 키 등을 환경 변수로 설정하여 사용합니다.
    if not KAKAO_BOT_ADMIN_KEY:
        print("경고: 메시지 발송을 위한 KAKAO_BOT_ADMIN_KEY 환경 변수가 설정되지 않았습니다.")
        return

    headers = {"Authorization": f"Bearer {KAKAO_BOT_ADMIN_KEY}"} # <--- 발송용 토큰 사용
    # API 엔드포인트 확인 필요 (예: https://kapi.kakao.com/v2/api/talk/memo/default/send 등)
    # payload 형식도 API 문서 확인 필요
    message_api_url = f"{KAKAO_API_URL}/v2/api/talk/memo/default/send" # 예시 URL (기본: 나에게 보내기)

    # 실제 메시지 페이로드 구성 (API 문서 참조)
    payload = {
        "template_object": {
            "object_type": "text",
            "text": text,
            "link": {
                "web_url": " ", # 웹 링크 (필요시)
                "mobile_web_url": " " # 모바일 웹 링크 (필요시)
            },
            "button_title": "" # 버튼 제목 (필요시)
        }
    }
    # 만약 특정 채팅방 ID로 보내는 API라면 payload 구조가 다를 수 있음
    # payload = {"receiver_uuids": f'["{chat_id}"]', "template_object": ...} # 예시 (친구에게 보내기 등)

    print(f"메시지 발송 요청: URL={message_api_url}, Headers={headers}, Payload={payload}")
    try:
        response = requests.post(message_api_url, json=payload, headers=headers)
        response.raise_for_status()
        print(f"메시지 발송 성공: {response.json()}")
    except requests.exceptions.RequestException as e:
        print(f"메시지 발송 실패: {e}")
        print(f"응답 내용: {response.text if 'response' in locals() else 'N/A'}")

if __name__ == "__main__":
    # 디버그 모드 활성화, SSL 필요시 설정 추가 가능
    app.run(host="0.0.0.0", port=8080, debug=True)