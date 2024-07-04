
import hashlib
import requests
import json
import base64
import random
import string
import json
import os
import hashlib
import time
import uuid
from datetime import datetime
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from datetime import datetime

class TPB:
    def __init__(self, username, password, account_number):
                # Public key in PEM format
        # Load the public key
        self.public_key = ""
        self.user_id = ""
        self.authToken = ""
        self.clientIp = ""
        self.session = requests.Session()
        self.guid = ""
        self.uuid = ""
        self.signNo = ""
        self.is_login = False
        self.key_captcha = "CAP-6C2884061D70C08F10D6257F2CA9518C"
        self.file = f"data/{username}.txt"
        self.url = {
    "getCaptcha": "https://ebank.tpb.com.vn/IBS-API-Gateway/corporate/captcha?guid=",
    "login": "https://biz.tpb.vn/gateway/api/auth/login?response=login&succeed=true",
    "getHistories": "https://biz.tpb.vn/gateway/api/casa-core-service/client-api/v1/account/casa/history/paging",
    "getSummary": "https://biz.tpb.vn/gateway/api/casa-core-service/client-api/v1/account/casa/history/summary",
    "getlistAccount": "https://biz.tpb.vn/gateway/api/casa-core-service/client-api/v1/account/casa?response=account-list&succeed=true",
}
        self.lang =  "vi"
        self.request_id = None
        self._timeout = 60
        self.is_get_user = False
        self.time_login = time.time()
        self.appVersion = ""
        self.clientOsVersion = "WINDOWS"
        self.browserVersion = "126.0.0.0"
        self.browserName = "Edge"
        self.deviceId = uuid.uuid4().hex
        self.screenResolution = "469x825"
        self.app_version = "1.0"
        self.challenge = ""
        self.defaultPublicKey = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAikqQrIzZJkUvHisjfu5Z\n\
CN+TLy//43CIc5hJE709TIK3HbcC9vuc2+PPEtI6peSUGqOnFoYOwl3i8rRdSaK1\n\
7G2RZN01MIqRIJ/6ac9H4L11dtfQtR7KHqF7KD0fj6vU4kb5+0cwR3RumBvDeMlB\n\
OaYEpKwuEY9EGqy9bcb5EhNGbxxNfbUaogutVwG5C1eKYItzaYd6tao3gq7swNH7\n\
p6UdltrCpxSwFEvc7douE2sKrPDp807ZG2dFslKxxmR4WHDHWfH0OpzrB5KKWQNy\n\
zXxTBXelqrWZECLRypNq7P+1CyfgTSdQ35fdO7M1MniSBT1V33LdhXo73/9qD5e5\n\
VQIDAQAB\n\
-----END PUBLIC KEY-----"
        self.clientPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCg+aN5HEhfrHXCI/pLcv2Mg01gNzuAlqNhL8ojO8KwzrnEIEuqmrobjMFFPkrMXUnmY5cWsm0jxaflAtoqTf9dy1+LL5ddqNOvaPsNhSEMmIUsrppvh1ZbUZGGW6OUNeXBEDXhEF8tAjl3KuBiQFLEECUmCDiusnFoZ2w/1iOZJwIDAQAB"
        self.clientPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n\
MIICXQIBAAKBgQCg+aN5HEhfrHXCI/pLcv2Mg01gNzuAlqNhL8ojO8KwzrnEIEuq\n\
mrobjMFFPkrMXUnmY5cWsm0jxaflAtoqTf9dy1+LL5ddqNOvaPsNhSEMmIUsrppv\n\
h1ZbUZGGW6OUNeXBEDXhEF8tAjl3KuBiQFLEECUmCDiusnFoZ2w/1iOZJwIDAQAB\n\
AoGAEGDV7SCfjHxzjskyUjLk8UL6wGteNnsdLGo8WtFdwbeG1xmiGT2c6eisUWtB\n\
GQH03ugLG1gUGqulpXtgzyUYcj0spHPiUiPDAPY24DleR7lGZHMfsnu20dyu6Llp\n\
Xup07OZdlqDGUm9u2uC0/I8RET0XWCbtOSr4VgdHFpMN+MECQQDbN5JOAIr+px7w\n\
uhBqOnWJbnL+VZjcq39XQ6zJQK01MWkbz0f9IKfMepMiYrldaOwYwVxoeb67uz/4\n\
fau4aCR5AkEAu/xLydU/dyUqTKV7owVDEtjFTTYIwLs7DmRe247207b6nJ3/kZhj\n\
gsm0mNnoAFYZJoNgCONUY/7CBHcvI4wCnwJBAIADmLViTcjd0QykqzdNghvKWu65\n\
D7Y1k/xiscEour0oaIfr6M8hxbt8DPX0jujEf7MJH6yHA+HfPEEhKila74kCQE/9\n\
oIZG3pWlU+V/eSe6QntPkE01k+3m/c82+II2yGL4dpWUSb67eISbreRovOb/u/3+\n\
YywFB9DxA8AAsydOGYMCQQDYDDLAlytyG7EefQtDPRlGbFOOJrNRyQG+2KMEl/ti\n\
Yr4ZPChxNrik1CFLxfkesoReXN8kU/8918D0GLNeVt/C\n\
-----END RSA PRIVATE KEY-----"
        self.init_guid()
        if not os.path.exists(self.file):
            self.username = username
            self.password = password
            self.account_number = account_number
            self.sessionId = ""
            self.cif = ""
            self.res = ""
            self.E = ""
            self.cifNo = ""
            self.browserId = hashlib.md5(self.username.encode()).hexdigest()
            self.save_data()
            
        else:
            self.parse_data()
            self.username = username
            self.password = password
            self.account_number = account_number
            
    def save_data(self):
        data = {
            'username': self.username,
            'password': self.password,
            'account_number': self.account_number,
            'sessionId': getattr(self, 'sessionId', ''),
            'deviceId': getattr(self, 'deviceId', ''),
            'public_key': self.public_key,
            'cif': getattr(self, 'cif', ''),
            'E': getattr(self, 'E', ''),
            'res': getattr(self, 'res', ''),
            'user_id': getattr(self, 'user_id', ''),
            'signNo': getattr(self, 'signNo', ''),
            'browserId': self.browserId,
            'cifNo': self.cifNo,
        }
        with open(self.file, 'w') as f:
            json.dump(data, f)

    def parse_data(self):
        with open(self.file, 'r') as f:
            data = json.load(f)
        self.username = data.get('username', '')
        self.password = data.get('password', '')
        self.account_number = data.get('account_number', '')
        self.sessionId = data.get('sessionId', '')
        self.deviceId = data.get('deviceId', '')
        self.public_key = data.get('public_key', '')
        self.token = data.get('token', '')
        self.accessToken = data.get('accessToken', '')
        self.authToken = data.get('authToken', '')
        self.cif = data.get('cif', '')
        self.res = data.get('res', '')
        self.user_id = data.get('user_id', '')
        self.signNo = data.get('signNo', '')
        self.browserId = data.get('browserId', '')
        self.E = data.get('E', '')
        self.cifNo = data.get('cifNo', '')
    def init_guid(self):
        timestamp = str(int(time.time()))
        self.uuid = str(uuid.uuid4())
        combined_string = f"{timestamp}{self.uuid}"
        self.guid = hashlib.md5(combined_string.encode()).hexdigest()
    def Ht(self,data):
        # Load the RSA key from the key string (in PEM format)
        key = f"-----BEGIN PUBLIC KEY-----\n{self.public_key}\n-----END PUBLIC KEY-----"
        rsa_key = RSA.import_key(key)

        # Encrypt the message using PKCS1 padding
        cipher = PKCS1_v1_5.new(rsa_key)

        ciphertext = cipher.encrypt(data.encode('utf-8'))

        # Encode the ciphertext as base64
        return base64.b64encode(ciphertext).decode('utf-8')
    def Kt(self):
        def replace_char(e):
            t = int(16 * random.random())
            if e == 'x':
                return hex(t)[2:]
            elif e == 'y':
                return hex((t & 0x3) | 0x8)[2:]

        uuid = ''.join(replace_char(e) if e in 'xy' else e for e in "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx")
        return uuid
    def pad(self,data):
        block_size = AES.block_size
        padding = block_size - len(data) % block_size
        return data + bytes([padding] * padding)
    def Ut(self,password, plaintext):
    # Generate random IV and salt
        iv = get_random_bytes(16)
        salt = get_random_bytes(16)

        # Derive key using PBKDF2
        key = PBKDF2(password.encode(), salt, dkLen=32, count=2000)

        # Pad the plaintext
        padded_plaintext = self.pad(plaintext.encode())

        # Encrypt the data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_plaintext)

        # Return the result
        return {
            'iv': iv.hex(),
            'salt': salt.hex(),
            'data': base64.b64encode(ciphertext).decode('utf-8')
        }
    def get_key_site(self):
        url = "https://onlinebanking.eximbank.com.vn/api/IB/KHDN/security/getPermission"

        payload = json.dumps({})
        headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Content-Type': 'application/json',
        'Origin': 'https://onlinebanking.eximbank.com.vn',
        'Referer': 'https://onlinebanking.eximbank.com.vn/KHDN/account/login-corp?returnUrl=%2Fhome',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
        'X-Token': '',
        'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }

        response = self.session.request("POST", url, headers=headers, data=payload)
        res = response.json()
        if 'ID' in res:
            self.public_key = res['ID']
        return res

    def curlPost(self, url, data):

        headers = {
        'Content-Type': 'application/json',
        'APP-VERSION': '1641283283523',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'DEVICE-ID': self.deviceId,
        'DEVICE-NAME': '126.0.0.0',
        'LANGUAGE': 'vi',
        'PLATFORM-NAME': 'WEB',
        'PLATFORM-VERSION': '126.0.0.0',
        'Referer': 'https://biz.tpb.vn/main',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
        'X-Requested-With': 'XMLHttpRequest',
        'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }
        if self.sessionId:
            headers['X-Token'] = self.sessionId
        response = self.session.post(url, headers=headers, data=json.dumps(data))
        # print(response.text)
        result = response.json()
        return result
    def curlGet(self, url):

        headers = {
        'Content-Type': 'application/json',
        'APP-VERSION': '1641283283523',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'DEVICE-ID': self.deviceId,
        'DEVICE-NAME': '126.0.0.0',
        'LANGUAGE': 'vi',
        'PLATFORM-NAME': 'WEB',
        'PLATFORM-VERSION': '126.0.0.0',
        'Referer': 'https://biz.tpb.vn/main',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
        'X-Requested-With': 'XMLHttpRequest',
        'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }
        if self.accessToken:
            headers['Authorization'] = 'Bearer ' + self.accessToken
        response = self.session.get(url, headers=headers)
        # print(response.text)
        result = response.json()
        return result

    def generate_request_id(self):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=12)) + '|' + str(int(datetime.now().timestamp()))
    def doLogin(self):
        param = {
            "accountType":  "CUSTOMER",
            "password": self.password,
            "username": self.username
        }

        result = self.curlPost(self.url['login'], param)
        if 'access_token' in result and 'user_name' in result:
            # self.cifNo = result['cifNo']
            self.accessToken = result['access_token']
            self.save_data()
            self.is_login = True
            self.time_login = time.time()
            return {
                'code': 200,
                'success': True,
                'message': "success",
                'access_token': self.accessToken,
                'data': result if result else ""
            }
        else:
            return {
                'code': 500,
                'success': False,
                'message': result['messages']['vn'] if 'messages' in result and 'vn' in result['messages'] else result,
                "param": param,
                'data': result if result else ""
            }

    def getE(self):
        ahash = hashlib.md5(self.username.encode()).hexdigest()
        imei = '-'.join([ahash[i:i+4] for i in range(0, len(ahash), 4)])
        return imei.upper()

    def getCaptcha(self):
        captchaToken = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        url = self.url['getCaptcha'] + captchaToken
        response = requests.get(url)
        result = base64.b64encode(response.content).decode('utf-8')
        return result
    def getPermissions(self):
        data = {
            "routerLink": "/home",
            "userId": self.user_id,
            "certId": self.user_id
        }
        e = json.dumps(data)
        r = self.Kt()
        i = self.Ut(r,e)
        s = f"{i['salt']}::{i['iv']}::{r}"
        param = {
                    'meta': self.Ht(s),
                    'data': i['data'],
                    'verified': True
                }
        result = self.curlPost(self.url['getPermissions'], param)
        return (result)
    def getNoteByMenuId(self):
        data = {
            "reqId": "100",
            "certId": self.user_id
        }
        e = json.dumps(data)
        r = self.Kt()
        i = self.Ut(r,e)
        s = f"{i['salt']}::{i['iv']}::{r}"
        param = {
                    'meta': self.Ht(s),
                    'data': i['data'],
                    'verified': True
                }
        result = self.curlPost(self.url['getNoteByMenuId'], param)
        return (result)
    def getlistAccount(self,account_number=None):
        if not account_number:
            account_number = self.account_number
        if not self.is_login or time.time() - self.time_login > 300:
            login = self.doLogin()
            if not login['success']:
                return login
        # permiss = self.getPermissions()
        # print (permiss)
        # getNoteByMenuId = self.getNoteByMenuId()
        # print (getNoteByMenuId)
        result = self.curlGet(self.url['getlistAccount'])
        if result and 'accountNumber' in result[0]:
            for account in result:
                if account_number == account['accountNumber']:
                    self.is_get_user = True
                    if float(account['availableBalance']) < 0 :
                        return {'code':448,'success': False, 'message': 'Blocked account with negative balances!',
                                'data': {
                                    'balance':float(account['availableBalance'])
                                }
                                }
                    else:
                        return {'code':200,'success': True, 'message': 'Thành công',
                                'data':{
                                    'account_number':account_number,
                                    'balance':float(account['availableBalance'])
                        }}
            return {'code':404,'success': False, 'message': 'account_number not found!'} 
        else: 
            return {'code':520 ,'success': False, 'message': 'Unknown Error!'} 


    def getHistories(self, fromDate="16/06/2023", toDate="16/06/2023", account_number='',page=0,size=300):
        if not self.is_login or time.time() - self.time_login > 300:
                login = self.doLogin()
                if not login['success']:
                    return login
        param = {
            "accountName": "",
            "accountNumber": account_number,
            "amountFlow": "ALL",
            "counterAccountNumber": "",
            "description": "",
            "fromAmount": 0,
            "fromDate": fromDate,
            "toAmount": 0,
            "toDate": toDate,
            "transactionCode": "",
            "transactionType": "ALL"
        }
        result = self.curlPost(self.url['getSummary'], param)
        if result and  'total' in result and 'maxEntryNo' in result:
            maxEntryNo = result['maxEntryNo']
            total_size = result['total']
            param = {
                "accountName": "",
                "accountNumber": account_number,
                "amountFlow": "ALL",
                "counterAccountNumber": "",
                "description": "",
                "fromAmount": 0,
                "fromDate": fromDate,
                "maxEntryNo": maxEntryNo,
                "paging": {"page": page, "size": size},
                "toAmount": 0,
                "toDate": toDate,
                "transactionCode": "",
                "transactionType": "ALL"
            }
            result = self.curlPost(self.url['getHistories'], param)
            if result and 'casaHisoryList' in result:
                return {'code':200,'success': True, 'message': 'Thành công',
                                'data':{
                                    'total': total_size,
                                    'transactions':result['casaHisoryList'],
                        }}
            else:
                return  {
                        "success": False,
                        "code": 503,
                        "message": "Service Unavailable!"
                    }
        return  {
            "success": False,
            "code": 503,
            "message": "Service Unavailable!"
        }

