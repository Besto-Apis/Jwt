from flask import Flask, Response,request
import time
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

def decrypt_api(cipher_text):
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(bytes.fromhex(cipher_text)), AES.block_size)
    return plain_text.hex()

def encrypt_api(plain_text):
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def Bes_Token(Token,Uid): 	        
        URL = "https://loginbp.common.ggbluefox.com/MajorLogin"
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB46',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjo5MjgwODkyMDE4LCJuaWNrbmFtZSI6IkJZVEV2R3QwIiwibm90aV9yZWdpb24iOiJNRSIsImxvY2tfcmVnaW9uIjoiTUUiLCJleHRlcm5hbF9pZCI6ImYzNGQyMjg0ZWJkYmFkNTkzNWJjOGI1NTZjMjY0ZmMwIiwiZXh0ZXJuYWxfdHlwZSI6NCwicGxhdF9pZCI6MCwiY2xpZW50X3ZlcnNpb24iOiIxLjEwNS41IiwiZW11bGF0b3Jfc2NvcmUiOjAsImlzX2VtdWxhdG9yIjpmYWxzZSwiY291bnRyeV9jb2RlIjoiRUciLCJleHRlcm5hbF91aWQiOjMyMzQ1NDE1OTEsInJlZ19hdmF0YXIiOjEwMjAwMDAwNSwic291cmNlIjoyLCJsb2NrX3JlZ2lvbl90aW1lIjoxNzE0NjYyMzcyLCJjbGllbnRfdHlwZSI6MSwic2lnbmF0dXJlX21kNSI6IiIsInVzaW5nX3ZlcnNpb24iOjEsInJlbGVhc2VfY2hhbm5lbCI6ImlvcyIsInJlbGVhc2VfdmVyc2lvbiI6Ik9CNDUiLCJleHAiOjE3MjIwNTkxMjF9.yYQZX0GeBMeBtMLhyCjSV0Q3e0jAqhnMZd3XOs6Ldk4',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }

   
        data = bytes.fromhex('1a13323032342d30392d30342030373a35383a3436220966726565206669726528013a07312e3130362e32423c416e64726f6964204f5320372e312e32202f204150492d32352028514b51312e3139303832352e3030322f31372e303234302e323030342e392d30294a0848616e6468656c645206524f474552535a045749464960800f68b80872033234307a1b41524d7637205646507633204e454f4e207c2032303030207c20348001d71b8a010f416472656e6f2028544d292035343092010d4f70656e474c20455320332e309a012b476f6f676c657c64333031303831302d383639392d346234612d393734332d393362363832343231646364a2010d34312e3233352e34372e313130aa0102656eb201206632343165633737636437363832346138636434383031313438396436346363ba010134c2010848616e6468656c64ca010f6173757320415355535f5a30315144ea014039326333613235653130653062326331346539393565363266366132373534613163396262313763626562306231306337303735323837613565653637386230f00101ca0206524f47455253d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003f6ee07e803e59207f003fe3df803e63080048fc6078804f6ee0790048fc6079804f6ee07c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044831643964626263353561613435646434396631333133343562613832353332627c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313137363833b205094f70656e474c455332b805ff7fc00504ca05251354164553550a034a000f4758594c0b146d0c050c5d0d200911046b1502520a4768590166d20505436169726fda050143e0058831ea0507616e64726f6964f2055c4b717348547746642b3437327575355a4d7975464b4a6e7551332b31486b62517771587a76665a506f4b4f6c733334505179426a4a2b45487958626f6c39634d306d31534b436a387779416b53426a5345626b5031617a6e626a673df805fbe406880601')
        OLD_ACCESS_TOKEN = "92c3a25e10e0b2c14e995e62f6a2754a1c9bb17cbeb0b10c7075287a5ee678b0"
        OLD_OPEN_ID = "f241ec77cd76824a8cd48011489d64cc"
        time.sleep(0.2)
        data = data.replace(OLD_OPEN_ID.encode(), Uid.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode(), Token.encode())
        d = encrypt_api(data)
        Final_Payload = bytes.fromhex(d)

        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False)
        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                return False
            BASE64_TOKEN = RESPONSE.text[RESPONSE.text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ"):-1]
            second_dot_index = BASE64_TOKEN.find(".", BASE64_TOKEN.find(".") + 1)
         
            time.sleep(0.2)
            BASE64_TOKEN = BASE64_TOKEN[:second_dot_index+44]
            return BASE64_TOKEN
        else:
            return False

@app.route('/Token-Jwt', methods=['GET'])
def get_token():
    Token = request.args.get('Token')
    Uid = request.args.get('Uid')

    if not Token or not Uid:
        return ' - Missing Access Token Or Uid ! ', 400

    with ThreadPoolExecutor(max_workers=5) as executor:
        future = executor.submit(Bes_Token, Token, Uid)
        response = future.result()

    if response:
        return Response(f' - Token: {response}', mimetype='text/plain')
    return Response(" - Error ! For Get Jwt Token", status=500, mimetype='text/plain')

if __name__ == '__main__':
    app.run(debug=False)
