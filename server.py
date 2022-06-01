
from hmac import digest
import hmac
from tokenize import cookie_re
from typing  import Optional
from urllib import response
from fastapi import FastAPI, Form , Cookie
from fastapi.responses import Response
import hmac
import hashlib
import base64

app = FastAPI()

SECRET_KEY= 'dccc26503be1bf9aabe26ea495517394ba30bd87253af0a2f76252b20221e78a'
PASSWORD_SALT = '3ae84be01b67ef60f638bdf724597597dc191056a5814747fe236a4c7d07099e'


def sign_data(data: str) -> str:
    '''Возвращает подписанные данные data'''
    return hmac.new(
        SECRET_KEY.encode(),
        msg = data.encode(),
        digestmod = hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign,sign):
        return username

def verify_password(username: str, password: str) -> bool:
    '''Сравнение хэша пароля в базе данных с веденными пользователем'''
    password_hash = hashlib.sha256( ( password + PASSWORD_SALT).encode() ) \
    .hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return  password_hash == stored_password_hash
        

users = {
    "alexey@user.com":{
        "name":'Алексей',
        "password":"07c249c38cfb6c1368bce2a92314c34c244848a1a6b4a0e62b279b8848152820",
        "balance": 100_000
    },
    "petr@user.com":{
        "name":"Петр",
        "password": "24512545f0ef7ac1379c668aa783dee3dfe9dab6e71d4c7a079218dd7cb8bea3",
        "balance": 555_555
    }
}



@app.get('/')
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('teamplates/login.html','r') as f:
        login_page = f.read()
        if not username:
            return Response(login_page,media_type='text/html')
        valid_username = get_username_from_signed_string(username)
        if not valid_username:
            response = Response(login_page,media_type='text/html')
            response.delete_cookie(key='username')
            return response

        try:
            user = users[valid_username]    
        except KeyError:
            response =  Response(login_page,media_type='text/html')
            response.delete_cookie(key='username')
            return response

    return Response(f"Привет {users[valid_username]['name']}",media_type='text/html')
    

@app.post('/login')
def process_login_page(username : str = Form(...), password : str= Form(...)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response('Я вас не знаю', media_type='text/html')


    response =  Response(
        f"Привет : {user['name']}! <br />Баланс: {user['balance']}",
        media_type='text/html')

    username_signed = base64.b64encode(username.encode()).decode() + '.' + \
        sign_data(username)
    response.set_cookie(key='username', value=username_signed)
    return response

    


