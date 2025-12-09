try:
    import ast, random, marshal, base64, bz2, zlib, lzma, time, sys, inspect, hashlib, os, sys, builtins, requests, types
    from ast import *
except Exception as e:
    print(e)

Izumkonata = ['__import__', 'abs', 'all', 'any', 'ascii', 'bin', 'breakpoint', 'callable', 'chr', 'compile', 'delattr', 'dir', 'divmod', 'eval', 'exec', 'format', 'getattr', 'globals', 'hasattr', 'hash', 'hex', 'id', 'input', 'isinstance', 'issubclass', 'iter', 'aiter', 'len', 'locals', 'max', 'min', 'next', 'anext', 'oct', 'ord', 'pow', 'print', 'repr', 'round', 'setattr', 'sorted', 'sum', 'vars', 'None', 'Ellipsis', 'NotImplemented', 'False', 'True', 'bool', 'memoryview', 'bytearray', 'bytes', 'classmethod', 'complex', 'dict', 'enumerate', 'filter', 'float', 'frozenset', 'property', 'int', 'list', 'map', 'range', 'reversed', 'set', 'slice', 'staticmethod', 'str', 'super', 'tuple', 'type', 'zip']
anti = """
print(' ' * len('>> Loading...'), end='\\r')

_check_ = __Konata__.__init__.__code__.co_consts
if '>> Loading...' not in _check_:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()

try:
    if str(AnhNguyenCoder('sys').exit) != '<built-in function exit>':
        raise Exception
    if str(print) != '<built-in function print>':
        raise Exception
    if str(exec) != '<built-in function exec>':
        raise Exception
    if str(input) != '<built-in function input>':
        raise Exception
    if str(len) != '<built-in function len>':
        raise Exception
    if str(AnhNguyenCoder('marshal').loads) != '<built-in function loads>':
        raise Exception

    with open(__file__, "rb") as f:
        raw = f.read()
    lines = raw.splitlines()

    if len(lines) != 63:
        raise Exception
    if b"__OBF__ = ('IzumKonataV2.0')" not in lines[1]:
        raise Exception
    if b"__OWN__ = ('Anhnguyencoder')" not in lines[2]:
        raise Exception
    if b"__USR__" not in lines[3]:
        raise Exception
    if b"__GBL__" not in lines[4]:
        raise Exception
    if b"__TELE__" not in lines[5]:
        raise Exception
    if b"__In4__" not in lines[6]:
        raise Exception
    if b"__CMT__" not in lines[7]:
        raise Exception

    with open(__file__, "r", encoding="utf-8", errors="ignore") as f:
        _line1 = f.readline().strip()

    if _line1 != "#!/bin/python3":
        raise Exception
    for i in range(1, 20):
        if b"#" in lines[i] and b"#!/bin/python3" not in lines[i]:
            raise Exception

except:
    try:
        with open(__file__, "wb") as f:
            f.write(b"")
    except:
        pass
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()

try:
    if str(AnhNguyenCoder('sys').exit) != '<built-in function exit>':
        raise Exception
    if str(print) != '<built-in function print>':
        raise Exception
    if str(exec) != '<built-in function exec>':
        raise Exception
    if str(input) != '<built-in function input>':
        raise Exception
    if str(len) != '<built-in function len>':
        raise Exception
    if str(AnhNguyenCoder('marshal').loads) != '<built-in function loads>':
        raise Exception
    if len(open(__file__, 'rb').read().splitlines()) != 63:
        raise Exception
    with open(__file__, "r", encoding="utf-8", errors="ignore") as f:
        _line1 = f.readline().strip()
    if _line1 != "#!/bin/python3":
        raise Exception
except:
    try:
        with open(__file__, "wb") as f:
            f.write(b"")
    except:
        pass
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()

with open(__file__, "r", encoding="utf-8") as f:
    cmt = f.readline().strip()
if cmt != "#!/bin/python3":
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()

if __Izumkonata__.__name__ != "__Izumkonata__":
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if ("__init__" not in __Izumkonata__.__dict__
    or "__call__" not in __Izumkonata__.__dict__
    or "__str__" not in __Izumkonata__.__dict__):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if id(__Izumkonata__.__init__) != id(__Izumkonata__.__dict__["__init__"]):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if id(__Izumkonata__.__call__) != id(__Izumkonata__.__dict__["__call__"]):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if id(__Izumkonata__.__str__) != id(__Izumkonata__.__dict__["__str__"]):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if __Izumkonata__.__init__.__code__.co_argcount < 1:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if __Izumkonata__.__call__.__code__.co_consts is None:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if __Izumkonata__.__str__.__code__.co_firstlineno < 1:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()

if __Anhnguyencoder__.__name__ != "__Anhnguyencoder__":
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if ("__getattribute__" not in __Anhnguyencoder__.__dict__
    or "__call__" not in __Anhnguyencoder__.__dict__
    or "__init__" not in __Anhnguyencoder__.__dict__):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if id(__Anhnguyencoder__.__init__) != id(__Anhnguyencoder__.__dict__["__init__"]):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if id(__Anhnguyencoder__.__getattribute__) != id(__Anhnguyencoder__.__dict__["__getattribute__"]):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if id(__Anhnguyencoder__.__call__) != id(__Anhnguyencoder__.__dict__["__call__"]):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if __Anhnguyencoder__.__getattribute__.__code__.co_argcount < 1:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()

if __OBF__ != ('IzumKonataV2.0'):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if __OWN__ != ('Anhnguyencoder'):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
_check_ = 0
for __c in __USR__:
    _check_ ^= ord(__c)
if _check_ != int(__GBL__):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if len(__USR__) < 3:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if __TELE__ != ('https://t.me/ctevclwar'):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if __In4__ != ('https://www.facebook.com/ng.xau.k25'):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if __CMT__ != {
    "EN": "Việc sử dụng obf này để lạm dụng mục đích xấu, người sở hữu sẽ không chịu trách nghiệm!",
    "VN": "Using this obf for bad purposes, the owner will not be responsible!"
}:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()

if __Konata__.__name__ != "__Konata__":
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if ("__init__" not in __Konata__.__dict__
    or "__call__" not in __Konata__.__dict__
    or "__str__" not in __Konata__.__dict__):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if id(__Konata__.__init__) != id(__Konata__.__dict__["__init__"]):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if id(__Konata__.__call__) != id(__Konata__.__dict__["__call__"]):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if id(__Konata__.__str__) != id(__Konata__.__dict__["__str__"]):
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if __Konata__.__init__.__code__.co_argcount < 1:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if __Konata__.__call__.__code__.co_argcount < 1:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if __Konata__.__str__.__code__.co_argcount < 1:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if __Konata__.__call__.__code__.co_consts is None:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if __Konata__.__init__.__code__.co_firstlineno < 1:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if __Konata__.__call__.__code__.co_firstlineno < 1:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if __Konata__.__str__.__code__.co_firstlineno < 1:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()


try:
    import requests, inspect, sys
except:
    print(">> Missing module: requests")
    __import__("sys").exit()
__rq = requests.request
__rq_src = inspect.getsourcefile(__rq) or ""
if "requests" not in __rq_src.replace("\\\\", "/").lower():
    print(">> AnhNguyenCoder...")
    __import__("sys").exit()
__sd = requests.sessions.Session.send
__sd_src = inspect.getsourcefile(__sd) or ""
if "requests" not in __sd_src.replace("\\\\", "/").lower():
    print(">> AnhNguyenCoder...")
    __import__("sys").exit()
if "sitecustomize" in sys.modules or "usercustomize" in sys.modules:
    print(">> AnhNguyenCoder...")
    __import__("sys").exit()

try:
    import requests, inspect, sys
except:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
__rq = requests.request
__rq_src = inspect.getsourcefile(__rq) or ""
if "requests" not in __rq_src.replace("\\\\", "/").lower():
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
__sd = requests.sessions.Session.send
__sd_src = inspect.getsourcefile(__sd) or ""
if "requests" not in __sd_src.replace("\\\\", "/").lower():
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()
if "sitecustomize" in sys.modules or "usercustomize" in sys.modules:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()

def __anh_force_exit__():
    try:
        import os
        os._exit(210)
    except:
        try:
            import ctypes
            ctypes.windll.kernel32.TerminateProcess(
                ctypes.windll.kernel32.GetCurrentProcess(), 210)
        except:
            try:

                import signal
                import os
                os.kill(os.getpid(), signal.SIGKILL)
            except:
                try:
                    import ctypes
                    NULL = ctypes.c_void_p()
                    ctypes.memmove(NULL, NULL, 1)
                except:

                    huge = []
                    while True:
                        huge.append(" " * 10000000)

try:
    import requests, sys, marshal, inspect, os, socket, ssl, http.client
    
    httptoolkit_envs = ['SSLKEYLOGFILE', 'HTTP_PROXY', 'HTTPS_PROXY']
    for env in httptoolkit_envs:
        if env in os.environ and 'httptoolkit' in os.environ.get(env, '').lower():
            print(">> AnhNguyenCoder...")
            __anh_force_exit__()
    if getattr(marshal.loads, "__module__", "") != "marshal":
        print(">> AnhNguyenCoder...")
        __anh_force_exit__()
    if getattr(requests.request, "__module__", "") != "requests.api":
        print(">> AnhNguyenCoder...")
        __anh_force_exit__()
    if getattr(requests.sessions.Session.send, "__module__", "") != "requests.sessions":
        print(">> AnhNguyenCoder...")
        __anh_force_exit__()
    if "sitecustomize" in sys.modules or "usercustomize" in sys.modules:
        print(">> AnhNguyenCoder...")
        __anh_force_exit__()
    __rq = requests.request
    __rq_src = inspect.getsourcefile(__rq) or ""
    if "requests" not in __rq_src.replace("\\\\", "/").lower():
        print(">> AnhNguyenCoder...")
        __anh_force_exit__()
    __sd = requests.sessions.Session.send
    __sd_src = inspect.getsourcefile(__sd) or ""
    if "requests" not in __sd_src.replace("\\\\", "/").lower():
        print(">> AnhNguyenCoder... [Session.send source changed]")
        __anh_force_exit__()
    if "socket.py" not in (socket.socket.__init__.__code__.co_filename or ""):
        print(">> AnhNguyenCoder...")
        __anh_force_exit__()
    if hasattr(ssl, '_create_default_https_context'):
        ctx = ssl._create_default_https_context()
        if not isinstance(ctx, ssl.SSLContext):
            print(">> AnhNguyenCoder...")
            __anh_force_exit__()

    try:
        import certifi
        if "httptoolkit" in certifi.where().lower():
            print(">> AnhNguyenCoder...")
            __anh_force_exit__()
    except:
        pass
    try:
        import urllib.request
        resp = urllib.request.urlopen('http://httpbin.org/get', timeout=5)
        data = resp.read().decode()
        if 'httptoolkit' in data.lower():
            print(">> AnhNguyenCoder... [connection intercepted]")
            __anh_force_exit__()
    except:
        pass

except Exception as e:
    print(f">> AnhNguyenCoder...")
    __anh_force_exit__()

import sys
_real_exit = sys.exit
def _patched_exit(code=0):
    __anh_force_exit__()
sys.exit = _patched_exit

if 'AnhNguyenCoder' in globals():
    _orig_anc = AnhNguyenCoder
    def _patched_anc(mod):
        if mod == 'sys':
            class FakeSys:
                def exit(self, code=0):
                    __anh_force_exit__()
            return FakeSys()
        return _orig_anc(mod)
    globals()['AnhNguyenCoder'] = _patched_anc

try:
    import requests, inspect, sys
    __rq = requests.request
    __rq_src = inspect.getsourcefile(__rq) or ""
    if "requests" not in __rq_src.replace("\\\\", "/").lower():
        raise Exception

    __sd = requests.sessions.Session.send
    __sd_src = inspect.getsourcefile(__sd) or ""
    if "requests" not in __sd_src.replace("\\\\", "/").lower():
        raise Exception
    if "sitecustomize" in sys.modules or "usercustomize" in sys.modules:
        raise Exception
except:
    try:
        with open(__file__, "wb") as f:
            f.write(b"")
    except:
        pass
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder("sys").exit()

try:
    _f = open(__file__, "rb").read().splitlines()

    if _f[0].strip() != b"#!/bin/python3":
        raise Exception
    if b"__OBF__ = ('IzumKonataV2.0')" not in _f[1]: raise Exception
    if b"__OWN__ = ('Anhnguyencoder')" not in _f[2]: raise Exception
    if b"__USR__" not in _f[3]: raise Exception
    if b"__GBL__" not in _f[4]: raise Exception
    if b"__TELE__" not in _f[5]: raise Exception
    if b"__In4__" not in _f[6]: raise Exception
except:
    try:
        open(__file__, "wb").write(b"")
    except:
        pass
    print(">> AnhNguyenCoder...")
    __import__("sys").exit()

"""
BANNER = """                                                      ⠀⠀⠀⠀⠀ ⢀⡀⠀⠔⢀⡀⠀⢀⠞⢠⠂
                                                             ⢸⠀⠘⢰⡃⠔⠩⠤⠦⠤⢀⡀
                                                     ⠀⠀⠀⠀⠀⢀⠄⢒⠒⠺⠆⠈⠀⠀⢐⣂⠤⠄⡀⠯⠕⣒⣒⡀
                                                          ⢐⡡⠔⠁⠆⠀⠀⠀⠀⠀⢀⠠⠙⢆⠀⠈⢁⠋⠥⣀⣀
 ⠀⠀   IZUMKONATA VERSION 1.0                          ⠈⠉⠀⠀⣰⠀⠀⠀⠀⡀⠀⢰⣆⢠⠠⢡⡀⢂⣗⣖⢝⡎⠉⠀⠀
 COPYRIGHT BY NGUYEN NHAT NAM ANH                    ⢠⡴⠛⠀⡇⠀⠐⠀⡄⣡⢇⠸⢸⢸⡇⠂⡝⠌⢷⢫⢮⡜⡀⠀⠀⠀⠀⠀⠀
⠀     HIGH SPEED OBFUSCATOR                              ⢰⣜⠘⡀⢡⠰⠳⣎⢂⣟⡎⠘⣬⡕⣈⣼⠢⠹⡟⠇⠀⠀⠀⠀⠀
   ADVANCED IZUMKONATA OBFUSCATOR    ⠀⠀⠀                ⠠⢋⢿⢳⢼⣄⣆⣦⣱⣿⣿⣿⣷⠬⣿⣿⣿⣿⠑⠵⠀⠀⠀⠀⠀⠀
                         ⠀⠀⠀⠀⠀                            ⡜⢩⣯⢝⡀⠁⠀⠙⠛⠛⠃⠀⠈⠛⠛⡿⠀⠀⠀⠀⠀⠀⠀⠀
⠀ __IzumKonata__⠀                       ⠀⠀⠀                 ⣿⠢⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀
__OWN_: AnhNguyenCoder⠀⠀                                   ⣀⡇⠀⠑⠀⠀⠀⠀⠐⢄⠄⢀⡼⠃
__OBF_: Optimized Encoding Speed!                         ⢸⣿⣷⣤⣀⠈⠲⡤⣀⣀⠀⡰⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
__CMT_: Anti-PYC Decompiler                              ⣼⣿⣿⣿⣿⣿⣶⣤⣙⣷⣅⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
__TELE_: https://t.me/ctevclwar⠀⠀⠀                    ⢀⣾⣿⣿⣿⣿⣻⢿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
__In4_: https://www.facebook.com/ng.xau.k25⠀         ⡠⠟⠁⠙⠟⠛⠛⢿⣿⣾⣿⣿⣿⣿⣧⡀"""

sys.setrecursionlimit(99999999)

ver = str(sys.version_info.major)+'.'+str(sys.version_info.minor)

try:
    from pystyle import *
except ModuleNotFoundError:
    print('>> Installing Module')
    __import__('os').system(f'pip{ver} install pystyle')
    from pystyle import *

System.Clear()


string = ''.join(random.sample(
    [chr(i) for i in range(0xAC00, 0xD7A4)], 
    10
))

cust = ''.join(random.sample(
    [chr(i) for i in range(0xAC00, 0xD7A4)], 
    10
))

e = dict(zip(string, cust))
d = {v: k for k, v in e.items()}

def var_con_cak2():
    return ''.join(random.choices([chr(i) for i in range(12356, 12544) if chr(i).isprintable() and chr(i).isidentifier()], k=11))

def var_con_cak1():
    return '_Izu__0x_' + ''.join(random.choices('ABCDXYZO0123456789', k=11))

def var_con_cak():
    return ''.join(random.choices([chr(i) for i in range(44032, 55204) if chr(i).isprintable() and chr(i).isidentifier()], k=11))

v = var_con_cak()
args = var_con_cak()
kwds = var_con_cak()
d = var_con_cak2()
k = var_con_cak1()
c = var_con_cak2()
arg_ = var_con_cak()
s = var_con_cak1()

def enc(s: str) -> str:
    noisy = s.encode().hex()                
    mapped = ''.join(e.get(c, c) for c in noisy)
    return f'{d}__AnhNGuyenCoder__{d}("{mapped}")'

Lobby = f"""#!/bin/python3
__OBF__ = ('IzumKonataV2.0')
__OWN__ = ('Anhnguyencoder')
__USR__ = ('__USER__')
__GBL__ = ('__GLOBALS__')
__TELE__ = ('https://t.me/ctevclwar')
__In4__ = ('https://www.facebook.com/ng.xau.k25')
__CMT__ = {{
    "EN": "Việc sử dụng obf này để lạm dụng mục đích xấu, người sở hữu sẽ không chịu trách nghiệm!",
    "VN": "Using this obf for bad purposes, the owner will not be responsible!"
}}

class __Izumkonata__:
    def __init__(anhnguyencoder, *{args}, **{kwds}):
        setattr(anhnguyencoder, "Cybers5", {enc('marshal')}); setattr(anhnguyencoder, "Cybers6", {cust}__huthuctu_{string}); setattr(anhnguyencoder, "Cybers7", {args}_lamba__{args})
    def __str__(anhnguyencoder, {arg_}):
        getattr(anhnguyencoder, "Cybers7")(getattr(AnhNguyenCoder(getattr(anhnguyencoder, "Cybers5")), {enc("loads")})({arg_}), globals())
    def __call__(anhnguyencoder, *{args}, **{kwds}):
        if 0: return Anhnguyen.{cust}({cust}[0]) if {args} else Anhnguyen
        IZUMKONATA = __{kwds}__({args}[0]).__{args}__()
        anhnguyencoder.__str__(IZUMKONATA)

class __Anhnguyencoder__:
    def __init__(anhnguyencoder, *{args}, **{kwds}):anhnguyencoder._{args} = {cust};Anhnguyencoder._{kwds} = {cust}
    def __getattribute__(anhnguyencoder, *{args}, **{kwds}):
        setattr(anhnguyencoder, "{args}", ("Cybers1"[0:]), {enc('base64')}); setattr(anhnguyencoder, "{args}", "Cybers2", {enc('bz2')}); setattr(anhnguyencoder, "{args}", ("Cybers3"[0:]), {enc('zlib')}); setattr(anhnguyencoder, "{args}", "Cybers4", {enc('lzma')})
        return Anhnguyen.{args}({cust}[0]) if {args} else Anhguyen
    def __call__(anhnguyencoder, *{args}, **{kwds}):return Anhnguyen.{args}({cust}[0]) if {args} else Anhnguyen

class __{kwds}__:
    def __init__(anhnguyencoder, *{args}, **{kwds}):
        setattr(anhnguyencoder, "Cybers1", {enc('base64')}); setattr(anhnguyencoder, "Cybers2", {enc('bz2')}); setattr(anhnguyencoder, "Cybers3", {enc('zlib')}); setattr(anhnguyencoder, "Cybers4", {enc('lzma')}); setattr(anhnguyencoder, "{arg_}", {args}[0])
    def __{args}__(a, *{args},**{kwds}):
        return getattr(AnhNguyenCoder(getattr(a,"Cybers4")),{enc("decompress")})(
               getattr(AnhNguyenCoder(getattr(a,"Cybers3")),{enc("decompress")})(
               getattr(AnhNguyenCoder(getattr(a,"Cybers2")),{enc("decompress")})(
               getattr(AnhNguyenCoder(getattr(a,"Cybers1")),{enc("a85decode")})
               (getattr(a,"{arg_}")))))

class __Konata__:
    def __call__(anhnguyencoder, *{args}, **{kwds}):
       if 0: return Anhnguyen.{cust}({cust}[0]) if {args} else Anhguyen; global __Deobf__, {cust}_ch3og5p3o5__{cust}, {string}, {cust}__huthuctu_{string}, {d}__AnhNGuyenCoder__{d}, {cust}__mol_{cust}, anhguyencoder, {cust}_cyber__{cust}, {string}__veli_{cust}, {c}, {args}_lamba__{args}, AnhNguyenCoder
       globals()['{cust}__mol_{cust}'] = eval('lave'[::-1]); globals()['anhguyencoder'] = {cust}__mol_{cust}('rts'[::-1]); globals()['{cust}_cyber__{cust}'] = {cust}__mol_{cust}('setyb'[::-1])
       globals()['{cust}_ch3og5p3o5__{cust}'] = "lambda((IzumKonata: ({string} - ({cust}[0])() - ({c})({cust}) + ({args})())())({arg_})"; globals()['{string}__veli_{cust}'] = {cust}__mol_{cust}(('tcid')[::-1])
       globals()['{string}'] = "lambda((IzumKonata: ({string} - ({cust}[0])() - ({c})({string}) + ({args})())())({arg_})"; globals()['{d}__AnhNGuyenCoder__{d}'] = lambda {s}: getattr({cust}_cyber__{cust}, "fromhex")(anhguyencoder().join(({d}.get({c}, {c}) for {c} in {s}))).decode(); globals()['{c}'] = {cust}__mol_{cust}('piz'[::-1])
       globals()['{cust}__huthuctu_{string}'] = {string}__veli_{cust}({c}({cust}_ch3og5p3o5__{cust}, {string})); {d} = {{{v}: {k} for {k}, {v} in {cust}__huthuctu_{string}.items()}}
       globals()['AnhNguyenCoder'] = {cust}__mol_{cust}({enc('__tropmi__')}[::-1]); globals()['{args}_lamba__{args}'] = {cust}__mol_{cust}({enc('cexe')}[::-1]); globals()['__Deobf__'] = {cust}__mol_{cust}({enc('tni')}[::-1])
    def __str__(anhnguyencoder, *{args}, **{kwds}):anhnguyencoder._{args} = {cust};Anhnguyencoder._{kwds} = {cust}
    def __init__(anhnguyencoder, *{args}, **{kwds}):
        if 0: return Anhnguyen.{cust}({cust}[0]) if {args} else Anhguyen
        if str(__import__("sys").version_info.major)+"."+str(__import__("sys").version_info.minor) != "{ver}":
            print(">> This code dont work in your python version")
            print(f'>> Your Current Python Version Is {{str(__import__("sys").version_info.major)+"."+str(__import__("sys").version_info.minor)}}. Please Install Python {ver} To Run The Program File!')
            __import__('sys').exit(__GLOBALS__)
        else:
            print(">> Loading...", end="\\r")

__Konata__()()

try:__Izumkonata__()(bytecode)
except Exception as {kwds}:
    print({kwds})
except KeyboardInterrupt:pass"""

def _args(name):
    return ast.arguments(
        posonlyargs=[],
        args=[ast.arg(arg=name)],
        vararg=None,
        kwonlyargs=[],
        kw_defaults=[],
        kwarg=None,
        defaults=[]
    )

def obfstr(s):
    lst=[ord(i) for i in s]; v=var_con_cak()
    lam3=ast.Lambda(
        args=_args(var_con_cak()),
        body=ast.Call(
            func=ast.Attribute(
                value=ast.Call(ast.Name('anhguyencoder',ast.Load()),[],[]),
                attr="join", ctx=ast.Load()
            ),
            args=[ast.GeneratorExp(
                elt=ast.Call(ast.Name("chr",ast.Load()),[ast.Name(v,ast.Load())],[]),
                generators=[ast.comprehension(
                    target=ast.Name(v,ast.Store()),
                    iter=ast.List([ast.Constant(x) for x in lst],ast.Load()),
                    ifs=[], is_async=0
                )]
            )],
            keywords=[]
        )
    )
    lam2=ast.Lambda(_args(var_con_cak()),
        ast.Call(lam3,[ast.Constant("AnhNguyenCoder")],[]))
    lam1=ast.Lambda(_args(var_con_cak()),
        ast.Call(lam2,[ast.Constant("AnhNguyenCoder")],[]))
    return ast.Call(lam1,[ast.Constant("AnhNguyenCoder")],[])

def anti_decompile(co):
    bc = bytearray(co.co_code)

    trash = bytes([random.randint(1, 255) for _ in range(30)])
    bc = trash + bc

    return types.CodeType(
        co.co_argcount,
        co.co_posonlyargcount,
        co.co_kwonlyargcount,
        co.co_nlocals,
        co.co_stacksize,
        co.co_flags,
        bytes(bc),
        co.co_consts,
        co.co_names,
        co.co_varnames,
        co.co_filename,
        co.co_name,
        co.co_firstlineno,
        co.co_lnotab,
        co.co_freevars,
        co.co_cellvars
    )

def _safe_source(obj):
    try:
        import inspect
        if hasattr(obj, "__code__") or hasattr(obj, "__file__"):
            return inspect.getsourcefile(obj) or ""
        return ""
    except:
        return ""

def obfint(i):
    haha=211-i
    lam3=ast.Lambda(_args(var_con_cak()),
        ast.Call(ast.Name("__Deobf__",ast.Load()),
            [ast.BinOp(ast.Constant(211),ast.Sub(),ast.Constant(haha))],[]))
    lam2=ast.Lambda(_args(var_con_cak()),
        ast.Call(lam3,[ast.Constant("AnhNguyenCoder")],[]))
    lam1=ast.Lambda(_args(var_con_cak()),
        ast.Call(lam2,[ast.Constant("AnhNguyenCoder")],[]))
    return ast.Call(lam1,[ast.Constant("AnhNguyenCoder")],[])

def joinstr(f):
    if not isinstance(f, ast.JoinedStr):
        return f
    vl = []
    for i in f.values:
        if isinstance(i, ast.Constant):
            vl.append(i)
        elif isinstance(i, ast.FormattedValue):
            value_expr = i.value
            if i.conversion == 115:
                value_expr = Call(func=Name(id='anhguyencoder', ctx=Load()), args=[value_expr], keywords=[])
            elif i.conversion == 114:
                value_expr = Call(func=Name(id='repr', ctx=Load()), args=[value_expr], keywords=[])
            elif i.conversion == 97:
                value_expr = Call(func=Name(id='ascii', ctx=Load()), args=[value_expr], keywords=[])
            if i.format_spec:
                if isinstance(i.format_spec, ast.JoinedStr):
                    spec_expr = joinstr(i.format_spec)
                elif isinstance(i.format_spec, ast.Constant):
                    spec_expr = i.format_spec
                elif isinstance(i.format_spec, ast.FormattedValue):
                    spec_parts = []
                    spec_value = i.format_spec.value
                    if i.format_spec.conversion == 115:
                        spec_value = Call(func=Name(id='anhguyencoder', ctx=Load()), args=[spec_value], keywords=[])
                    elif i.format_spec.conversion == 114:
                        spec_value = Call(func=Name(id='repr', ctx=Load()), args=[spec_value], keywords=[])
                    elif i.format_spec.conversion == 97:
                        spec_value = Call(func=Name(id='ascii', ctx=Load()), args=[spec_value], keywords=[])
                    spec_expr = spec_value
                else:
                    spec_expr = i.format_spec
                value_expr = Call(func=Name(id='format', ctx=Load()), args=[value_expr, spec_expr], keywords=[])
            elif i.conversion == -1:
                value_expr = Call(func=Name(id='anhguyencoder', ctx=Load()), args=[value_expr], keywords=[])
            vl.append(value_expr)
        elif hasattr(i, 'values') and isinstance(i, ast.JoinedStr):
            vl.append(joinstr(i))
        else:
            vl.append(Call(func=Name(id='anhguyencoder', ctx=Load()), args=[i], keywords=[]))
    if not vl:
        return Constant(value='')
    if len(vl) == 1 and isinstance(vl[0], ast.Constant):
        return vl[0]
    return Call(func=Attribute(value=Constant(value=''), attr='join', ctx=Load()), args=[Tuple(elts=vl, ctx=Load())], keywords=[])

class cv(ast.NodeTransformer):

    def visit_JoinedStr(self, node):
        node = joinstr(node)
        return node

class hide(ast.NodeTransformer):

    def visit_Name(self, node):
        if node.id in Izumkonata:
            node = Call(func=Name(id='getattr', ctx=Load()), args=[Call(func=Name(id='AnhNguyenCoder', ctx=Load()), args=[Constant(value='builtins')], keywords=[]), Constant(value=node.id)], keywords=[])
        return node
    
class obf(ast.NodeTransformer):

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            node = obfstr(node.value)
        elif isinstance(node.value, int):
            node = obfint(node.value)
        return node

def gen_jcode(code):
    men = var_con_cak()
    anhnguyencoder = var_con_cak()
    izumkonata = var_con_cak()
    return [Assign(targets=[Name(id=anhnguyencoder, ctx=Store())], value=Constant(value=men), lineno=0), Assign(targets=[Name(id=izumkonata, ctx=Store())], value=Constant(value=True), lineno=0), If(test=BoolOp(op=And(), values=[Compare(left=Name(id=anhnguyencoder, ctx=Load()), ops=[Eq()], comparators=[Constant(value=men)]), Compare(left=Name(id=izumkonata, ctx=Load()), ops=[NotEq()], comparators=[Constant(value=True)])]), body=[Expr(value=Lambda(args=arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]), body=Constant(value='dec cai mau lol')))], orelse=[If(test=BoolOp(op=And(), values=[Compare(left=Name(id=anhnguyencoder, ctx=Load()), ops=[Eq()], comparators=[Constant(value=men)]), Compare(left=Name(id=izumkonata, ctx=Load()), ops=[NotEq()], comparators=[Constant(value=False)])]), body=[Try(body=[Expr(value=Tuple(elts=[BinOp(left=Constant(value=1), op=Div(), right=Constant(value=0)), BinOp(left=Constant(value=123), op=Div(), right=Constant(value=0)), BinOp(left=Constant(value=12312321312), op=Div(), right=Constant(value=0))], ctx=Load()))], handlers=[ExceptHandler(body=[Pass()])], orelse=[], finalbody=[])], orelse=[If(test=BoolOp(op=Or(), values=[Compare(left=Name(id=anhnguyencoder, ctx=Load()), ops=[Eq()], comparators=[Constant(value='izu')]), Compare(left=Name(id=izumkonata, ctx=Load()), ops=[Eq()], comparators=[Constant(value=False)])]), body=[Expr(value=Call(func=Lambda(args=arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]), body=Call(func=Name(id='print', ctx=Load()), args=[Constant(value='bietdepzairoi')], keywords=[])), args=[], keywords=[]))], orelse=[While(test=Constant(value=True), body=[Pass()], orelse=[]), Expr(value=Call(func=Name(id='print', ctx=Load()), args=[Constant(value='deccailolnhamay')], keywords=[]))])])])]

class junk(ast.NodeTransformer):

    def visit_Module(self, node):
        for i, j in enumerate(node.body):

            if isinstance(j, (ast.FunctionDef, ast.ClassDef)):
                self.visit(j)

            junk_blocks = [gen_jcode(j) for _ in range(8)]

            node.body[i] = junk_blocks + [j]

        return node

    def visit_FunctionDef(self, node):
        for i, j in enumerate(node.body):
            junk_blocks = [gen_jcode(j) for _ in range(8)]
            node.body[i] = junk_blocks + [j]
        return node

    def visit_ClassDef(self, node):
        for i, j in enumerate(node.body):
            junk_blocks = [gen_jcode(j) for _ in range(8)]
            node.body[i] = junk_blocks + [j]
        return node

print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), BANNER))
print()
cyyy =  Colors.StaticMIX((Col.light_blue, Col.light_gray, Col.light_red))

try:
    while True:
        file_name = input(Colorate.Diagonal(
            Colors.DynamicMIX((Col.blue, Col.gray)), 
            ">> Enter File: "
        ))

        try:
            with open(file_name, "r", encoding="utf-8") as f:
                code = ast.parse(anti + f.read())
            break
        except FileNotFoundError:
            print(Colorate.Horizontal(Colors.green_to_blue, "File Not Found!\n"))

except KeyboardInterrupt:
    print()
    print(Colorate.Horizontal(Colors.blue_to_cyan, ">> Exiting...\n"))
    sys.exit()

user_name = input(Colorate.Diagonal(
    Colors.DynamicMIX((Col.blue, Col.gray)),
    ">> Enter Your Username! [For example: 'AnhNguyenCoder']: "
))

high_security = True if input(Colorate.Diagonal(
    Colors.DynamicMIX((Col.blue, Col.gray)),
    ">> Do you want high security? Yes (Y) | (N) No: "
)) != 'n' else False

hide_builtins = True if input(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), ">> Anti-Crack? (Y) Yes | (N) No: ")) != 'n' else False

junk_code = True if input(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), ">> Anti-Debug? (Y) Yes | (N) No: ")) != 'n' else False

print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), '[...] Start Encode...'))
st = time.time()
print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), '[...] Executing conversion...'))
cv().visit(code)

if hide_builtins:
    print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), '[...] Hide Builtins...'))
    hide().visit(code)

print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), '[...] Disturbing...'))
obf().visit(code)

if junk_code:
    print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), '[...] Executing more junk code...'))
    junk().visit(code)

print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), '[...] Compiling...'))
code = marshal.dumps(compile(ast.unparse(code), '<IZUMKONATA>', 'exec'))

def color_loading():
    for i in range(101):
        text = f">> Encoding... {i}%"
        colored = Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.green)), text)
        sys.stdout.write("\r" + colored)
        sys.stdout.flush()
        time.sleep(3/100)

    sys.stdout.write("\r" + " " * 80 + "\r")
    sys.stdout.flush()
color_loading()
print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.green)), '>> Adding Last Layer << '))
code = base64.a85encode(bz2.compress(zlib.compress(lzma.compress(code))))

final_usr = f"[Premium - {user_name} - main - Request Protection !]"

usr_crc = 0
for c in final_usr:
    usr_crc ^= ord(c)
final_gbl = f'{str(usr_crc)}'

final_output = Lobby.replace("bytecode", str(code))
final_output = final_output.replace("__USER__", final_usr)
final_output = final_output.replace("__GLOBALS__", final_gbl)

open("obf-"+file_name,'wb').write(final_output.encode())
print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), f'-> Execution time {time.time()-st:.3f}s'))
print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), f'-> Saved file name {"obf-"+file_name}'))