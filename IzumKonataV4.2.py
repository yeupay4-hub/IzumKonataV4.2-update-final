try:
    import ast, random, marshal, base64, bz2, zlib, lzma, time, sys, inspect, hashlib, os, sys, builtins, requests, types, traceback
    import string as _string
    from pystyle import Add,Center,Anime,Colors,Colorate,Write,System
    from sys import platform
    from ast import *
except Exception as e:
    print(e)

Izumkonata = ['__import__', 'abs', 'all', 'any', 'ascii', 'bin', 'breakpoint', 'callable', 'chr', 'compile', 'delattr', 'dir', 'divmod', 'eval', 'exec', 'format', 'getattr', 'globals', 'hasattr', 'hash', 'hex', 'id', 'input', 'isinstance', 'issubclass', 'iter', 'aiter', 'len', 'locals', 'max', 'min', 'next', 'anext', 'oct', 'ord', 'pow', 'print', 'repr', 'round', 'setattr', 'sorted', 'sum', 'vars', 'None', 'Ellipsis', 'NotImplemented', 'False', 'True', 'bool', 'memoryview', 'bytearray', 'bytes', 'classmethod', 'complex', 'dict', 'enumerate', 'filter', 'float', 'frozenset', 'property', 'int', 'list', 'map', 'range', 'reversed', 'set', 'slice', 'staticmethod', 'str', 'super', 'tuple', 'type', 'zip', 'print', 'MemoryError', '__dict__']

antitamper3 = r"""
import sys, os, inspect, subprocess, platform, builtins
def ___ok__finally__():
    if not inspect.isbuiltin(open) or not inspect.isbuiltin(builtins.__import__):
        if "__file__" in globals():
            open(__file__, "wb").close()
        raise MemoryError('>> AnhNguyenCoder...')
    r = sys.modules.get("requests")
    if r:
        try:
            if "site-packages" not in inspect.getsourcefile(r.sessions.Session.request):
                if "__file__" in globals():
                    open(__file__, "wb").close()
                raise MemoryError('>> AnhNguyenCoder...')
        except:
            raise MemoryError('___ok__finally__()')
    if platform.system().lower() != 'windows':
        return
    __covekhacang__ = ['wireshark', 'httptoolkit', 'fiddler', 'charles', 'burp', 'tcpdump']
    try:
        output = subprocess.check_output('tasklist', shell=True, text=True)
    except Exception:
        return
    output = output.lower()
    for s in __covekhacang__:
        if s.lower() in output:
            if "__file__" in globals():
                open(__file__, "wb").close()
            raise MemoryError('>> AnhNguyenCoder...')
___ok__finally__()
__import__('sys').modules.pop('requests', None)

def __anti_hook_url__():
    import sys, inspect
    def self_destruct():
        try:
            if "__file__" in globals():
                open(__file__, "wb").close()
        except:
            pass
        print(">> AnhNguyenCoder...")
        sys.exit(210)

    try:
        from requests.sessions import Session
    except:
        return

    Original = Session.__dict__.get("request")
    if not callable(Original):
        return

    def yeu_cau_bao_ve(self, method, url, **kwargs):
        if Session.request is not yeu_cau_bao_ve:
            self_destruct()

        try:
            src = inspect.getsource(Session.request).lower()
            if ("print" in src or "log" in src) and "url" in src:
                self_destruct()
        except:
            pass
        return Original(self, method, url, **kwargs)
    Session.request = yeu_cau_bao_ve

__anti_hook_url__()

def hide_url_requests():
    import sys, logging, re, builtins
    try:
        real_print = builtins.print

        def safe_print(*args, **kwargs):
            new_args = []
            for a in args:
                if isinstance(a, str):
                    a = re.sub(r'https?://\S+', '', a)
                new_args.append(a)
            real_print(*new_args, **kwargs)

        setattr(builtins, "print", safe_print)
    except:
        pass

    try:
        from requests.adapters import HTTPAdapter
        original_send = HTTPAdapter.send

        def safe_send(self, request, **kwargs):
            response = original_send(self, request, **kwargs)

            try:
                response.url = ""
                if hasattr(response, "request"):
                    response.request.url = ""
            except:
                pass
            return response
        HTTPAdapter.send = safe_send
    except:
        pass
    try:
        import http.client
        http.client.HTTPConnection.debuglevel = 0
        http.client.HTTPSConnection.debuglevel = 0
    except:
        pass

    logging.getLogger("urllib3").setLevel(logging.CRITICAL)
    logging.getLogger("requests").setLevel(logging.CRITICAL)
    logging.getLogger("urllib3.connectionpool").disabled = True

    sys.settrace(None)
hide_url_requests()
"""
antitamper2 = """
import sys, os, builtins, inspect

def anti_tamper():
    try:
        for name in ("exec", "eval", "print", "__import__", "open"):
            if not hasattr(builtins, name):
                raise MemoryError("Anhnguyencoder...")
            func = getattr(builtins, name)
            if hasattr(func, "__wrapped__") or hasattr(func, "__code__"):
                raise MemoryError("Anhnguyencoder...")
            if "built-in function" not in str(func):
                raise MemoryError("Anhnguyencoder...")

        for frame in inspect.stack():
            fname = (frame.filename or "").lower()
            if any(x in fname for x in ["pydevd", "debugpy", "pdb", "frida", "uncompyle"]):
                raise MemoryError("Anhnguyencoder...")
    except SystemExit:
        raise
    except:
        raise MemoryError("Anhnguyencoder...")

def __checkenvironment__():
    try:
        if hasattr(sys, "gettrace") and sys.gettrace():
            raise MemoryError("Anhnguyencoder...")
        if "PYTHONDEBUG" in os.environ:
            raise MemoryError("Anhnguyencoder...")
        if "PYTHONPATH" in os.environ:
            raise MemoryError("Anhnguyencoder...")
    except SystemExit:
        raise
    except:
        pass

def check_debugger():
    if os.name != "nt":
        return
    try:
        import ctypes

        if ctypes.windll.kernel32.IsDebuggerPresent():
            raise MemoryError("Anhnguyencoder...")
        is_remote = ctypes.c_int(0)
        ctypes.windll.kernel32.CheckRemoteDebuggerPresent(-1, ctypes.byref(is_remote))
        if is_remote.value:
            raise MemoryError("Anhnguyencoder...")
    except:
        pass

def anti_hook_check():
    try:
        debuggers = ['pydevd', 'debugpy', 'ptvsd', 'pdb']
        for dbg in debuggers:
            if dbg in sys.modules:
                raise MemoryError("Anhnguyencoder...")

        for func_name in ["print", "__import__", "exec", "eval"]:
            if hasattr(builtins, func_name):
                func = getattr(builtins, func_name)
                if hasattr(func, "__wrapped__") or hasattr(func, "__code__"):
                    raise MemoryError("Anhnguyencoder...")

    except SystemExit:
        raise
    except:
        pass

class __RuntimeHook__:
    def __init__(self):
        try:
            self.p = builtins.print
            self.e = builtins.exec
            self.v = builtins.eval
        except:
            self.p = self.e = self.v = None

    def check(self):
        try:
            if self.p and builtins.print != self.p:
                raise MemoryError("Anhnguyencoder...")
            if self.e and builtins.exec != self.e:
                raise MemoryError("Anhnguyencoder...")
            if self.v and builtins.eval != self.v:
                raise MemoryError("Anhnguyencoder...")
        except SystemExit:
            raise
        except:
            pass

def checks():
    try:
        warnings = []
        if hasattr(sys, "gettrace") and sys.gettrace():
            warnings.append("trace")
        debug_mods = ['pydevd', 'debugpy', 'pdb', 'bdb']
        for m in debug_mods:
            if m in sys.modules:
                warnings.append(m)
        for name in ['print', 'exec', 'eval', '__import__']:
            f = getattr(builtins, name, None)
            if f and (hasattr(f, "__wrapped__") or hasattr(f, "__code__")):
                warnings.append(name)
        if warnings:
            raise MemoryError("Anhnguyencoder...")
    except SystemExit:
        raise
    except:
        raise MemoryError("Anhnguyencoder...")

anti_tamper()
__checkenvironment__()
check_debugger()
anti_hook_check()
checks()

__rt = __RuntimeHook__()
__rt.check()

try:
    import sys, os
    if {'sitecustomize','usercustomize'} & sys.modules.keys(): exit(0)
    if any(os.path.isfile(p+os.sep+f) for p in sys.path if p for f in ('sitecustomize.py','usercustomize.py')): exit(0)
    import urllib3
    from urllib3 import PoolManager
    m = getattr(urllib3, '__file__', '').replace('\\\\','/')
    r = PoolManager.request
    if (not m or 'site-packages' not in m
        or not hasattr(r,'__code__')
        or 'urllib3' not in r.__code__.co_filename.replace('\\\\','/')
        or hasattr(r,'__wrapped__')):
        print("Anhnguyencoder...")
        raise MemoryError(print)
except:
    try:
        with open(__file__, "wb") as f:
            f.write(b"")
    except:
        pass
    print("Anhnguyencoder...")
    raise MemoryError(print)
"""

antitamper1 = """
try:
    _vm = 0
    import uuid, socket, multiprocessing, platform
    mac = ':'.join('%02x' % ((uuid.getnode() >> i) & 0xff) for i in range(0,48,8))[::-1]
    if mac.startswith(('00:05:69','00:0c:29','00:1c:14','00:50:56','08:00:27')):
        _vm += 2
    if any(x in socket.gethostname().lower() for x in ('vmware','vbox','virtual','qemu','xen')):
        _vm += 1
    if multiprocessing.cpu_count() <= 1:
        _vm += 1
    if platform.system() == "Linux":
        try:
            if 'hypervisor' in open('/proc/cpuinfo','r').read().lower():
                _vm += 2
        except:
            pass
    if _vm >= 3:
        open(__file__,'wb').write(b'')
        __import__('sys').exit()
except:
    print(">> AnhNguyenCoder...")
    __import__("sys").exit()

_check_memory_dump_ = False
try:
    _os = AnhNguyenCoder('os')
    if _os.name == 'nt':
        _ctypes = AnhNguyenCoder('ctypes')
        
        kernel32 = _ctypes.windll.kernel32
        if kernel32.IsDebuggerPresent():
            _check_memory_dump_ = True

        is_remote_debugging = _ctypes.c_int(0)
        kernel32.CheckRemoteDebuggerPresent(-1, _ctypes.byref(is_remote_debugging))
        if is_remote_debugging.value:
            _check_memory_dump_ = True
except:
    pass

if _check_memory_dump_:
    try:
        with open(__file__, "wb") as f:
            f.write(b"")
    except:
        pass
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()

_check_sandbox_ = False
try:
    _time = AnhNguyenCoder('time')
    _start_time = _time.time()
    _sum = 0
    for i in range(100000):
        _sum += i * i
        if _sum > 1000000000:
            _sum = 0
    
    _end_time = _time.time()
    _elapsed = _end_time - _start_time

    if _elapsed < 0.01 or _elapsed > 10.0:
        _check_sandbox_ = True
except:
    pass

try:
    _socket = AnhNguyenCoder('socket')
    _hostname = _socket.gethostname().lower()

    _sandbox_names = ['sandbox', 'malware', 'virus', 'analysis', 
                     'vmware', 'virtualbox', 'vbox', 'qemu', 'xen',
                     'test', 'lab', 'sample']
    
    for _name in _sandbox_names:
        if _name in _hostname:
            _check_sandbox_ = True
            break
except:
    pass

try:
    _os = AnhNguyenCoder('os')
    import multiprocessing
    if multiprocessing.cpu_count() < 2:
        _check_sandbox_ = True
except:
    pass

try:
    _psutil = AnhNguyenCoder('psutil')
    if hasattr(_psutil, 'virtual_memory'):
        _memory = _psutil.virtual_memory()
        if _memory.total < 2 * 1024**3:
            _check_sandbox_ = True
except:
    pass

try:
    _ctypes = AnhNguyenCoder('ctypes')
    
    class _POINT(_ctypes.Structure):
        _fields_ = [("x", _ctypes.c_long), ("y", _ctypes.c_long)]
    
    _pt = _POINT()
    _ctypes.windll.user32.GetCursorPos(_ctypes.byref(_pt))
    
    if _pt.x == 0 and _pt.y == 0:
        _time = AnhNguyenCoder('time')
        _time.sleep(1)
        _ctypes.windll.user32.GetCursorPos(_ctypes.byref(_pt))
        if _pt.x == 0 and _pt.y == 0:
            _check_sandbox_ = True
except:
    pass

if _check_sandbox_:
    try:
        with open(__file__, "wb") as f:
            f.write(b"")
    except:
        pass
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()

try:
    _vm_score = 0
    _dbg_score = 0
    _sb_score  = 0

    def __flag_vm(w=1):
        global _vm_score
        _vm_score += w
    def __flag_dbg(w=1):
        global _dbg_score
        _dbg_score += w
    def __flag_sb(w=1):
        global _sb_score
        _sb_score += w

    try:
        pass
    except:
        pass
    try:
        pass
    except:
        pass
    try:
        pass
    except:
        pass

    _risk = (_vm_score * 3) + (_sb_score * 2) + _dbg_score
    if _risk >= 3:
        raise Exception
except:
    try:
        open(__file__, "wb").write(b"")
    except:
        pass
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()

_check_ = __Konata__.__init__.__code__.co_consts
if '>> Loading...' not in _check_:
    with open(__file__, "wb") as f:
        f.write(b"")
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
    off = 1 if lines and lines[0] == b"#!/bin/python3" else 0
    if len(lines) != 54:
        raise Exception
    if b"__OBF__ = ('IzumKonataV4.2')" not in lines[1 + off]:
        raise Exception
    if b"__OWN__ = ('Anhnguyencoder')" not in lines[2 + off]:
        raise Exception
    if b"__USR__" not in lines[3 + off]:
        raise Exception
    if b"__GBL__" not in lines[4 + off]:
        raise Exception
    if b"__TELE__" not in lines[5 + off]:
        raise Exception
    if b"__In4__" not in lines[6 + off]:
        raise Exception
    if b"__CMT__" not in lines[7 + off]:
        raise Exception

    with open(__file__, "r", encoding="utf-8", errors="ignore") as f:
        _line1 = f.readline().strip()

    if off == 1:
        with open(__file__, "r", encoding="utf-8", errors="ignore") as f:
            f.readline()
            _line1 = f.readline().strip()
    if _line1 != "# -*- coding: utf-8 -*-":
        raise Exception

    for i in range(1 + off, 49 + off):
        if b"#" in lines[i] and b"# -*- coding: utf-8 -*-" not in lines[i]:
            raise Exception
except:
    try:
        with open(__file__, "wb") as f:
            f.write(b"")
    except:
        pass
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()

print(' ' * len('>> Loading...'), end='\\r')

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

    import sys
    if 'dis' in sys.modules:
        raise Exception
    if 'opcode' in sys.modules:
        raise Exception
    if 'inspect' in sys.modules:
        raise Exception
    if hasattr(sys, 'gettrace') and sys.gettrace():
        raise Exception

    import inspect
    for f in inspect.stack():
        fn = f.filename.lower()
        if 'dis' in fn or 'inspect' in fn or 'opcode' in fn:
            raise Exception

    fr = sys._getframe(0)
    consts = fr.f_code.co_consts

    if not consts or len(consts) < 3:
        raise Exception

    for c in consts:
        if isinstance(c, (bytes, bytearray)) and len(c) > 200:
            raise Exception

    def _deep_tuple(o, d=0):
        if d > 6:
            return True
        if isinstance(o, tuple):
            for i in o:
                if _deep_tuple(i, d + 1):
                    return True
        return False

    for c in consts:
        if _deep_tuple(c):
            raise Exception
    for c in consts:
        if isinstance(c, str):
            if "MARSHAL" in c or "DISASM" in c or "BYTECODE" in c:
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

    raw_lines = open(__file__, 'rb').read().splitlines()
    if len(raw_lines) != 54:
        raise Exception

    off = 1 if raw_lines and raw_lines[0] == b"#!/bin/python3" else 0

    with open(__file__, "r", encoding="utf-8", errors="ignore") as f:
        if off:
            f.readline()
        _line1 = f.readline().strip()

    if _line1 != "# -*- coding: utf-8 -*-":
        raise Exception

    for line in raw_lines[-3:]:
        if b"#" in line:
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
    if off:
        f.readline()
    cmt = f.readline().strip()

if cmt != "# -*- coding: utf-8 -*-":
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()

def _die():
    print(">> AnhNguyenCoder...")
    try:
        import os
        os.remove(__file__)
    except Exception:
        pass
    AnhNguyenCoder('sys').exit()

cls = __Izumkonata__
if cls.__name__ != "__Izumkonata__":
    _die()
if not all(k in cls.__dict__ for k in ("__init__", "__call__", "__str__")):
    _die()
if id(cls.__init__) != id(cls.__dict__["__init__"]):
    _die()
if id(cls.__call__) != id(cls.__dict__["__call__"]):
    _die()
if id(cls.__str__) != id(cls.__dict__["__str__"]):
    _die()
if cls.__init__.__code__.co_argcount < 1:
    _die()
if cls.__call__.__code__.co_consts is None:
    _die()
if cls.__str__.__code__.co_firstlineno < 1:
    _die()

def _die():
    print(">> AnhNguyenCoder...")
    try:
        import os
        os.remove(__file__)
    except:
        pass
    AnhNguyenCoder('sys').exit()
cls = __Anhnguyencoder__
if cls.__name__ != "__Anhnguyencoder__":
    _die()
if not all(k in cls.__dict__ for k in ("__getattribute__", "__call__", "__init__")):
    _die()
if id(cls.__init__) != id(cls.__dict__["__init__"]):
    _die()
if id(cls.__getattribute__) != id(cls.__dict__["__getattribute__"]):
    _die()
if id(cls.__call__) != id(cls.__dict__["__call__"]):
    _die()
if cls.__getattribute__.__code__.co_argcount < 1:
    _die()

def _die():
    print(">> AnhNguyenCoder...")
    try:
        import os
        os.remove(__file__)
    except Exception:
        pass
    AnhNguyenCoder('sys').exit()

if __OBF__ != 'IzumKonataV4.2':
    _die()
if __OWN__ != 'Anhnguyencoder':
    _die()
_check_ = 0
for __c in __USR__:
    _check_ ^= ord(__c)
if _check_ != int(__GBL__):
    _die()
if len(__USR__) < 3:
    _die()
if __TELE__ != 'https://t.me/ctevclwar':
    _die()
if __In4__ != 'https://www.facebook.com/ng.xau.k25':
    _die()
if __CMT__ != {
    "EN": "Việc sử dụng obf này để lạm dụng mục đích xấu, người sở hữu sẽ không chịu trách nghiệm!",
    "VN": "Using this obf for bad purposes, the owner will not be responsible!"
}:
    _die()

def _die():
    print(">> AnhNguyenCoder...")
    try:
        import os
        os.remove(__file__)
    except Exception:
        pass
    AnhNguyenCoder('sys').exit()
cls = __Konata__
if cls.__name__ != "__Konata__":
    _die()
if ("__init__" not in cls.__dict__
    or "__call__" not in cls.__dict__
    or "__str__" not in cls.__dict__):
    _die()
if id(cls.__init__) != id(cls.__dict__["__init__"]):
    _die()
if id(cls.__call__) != id(cls.__dict__["__call__"]):
    _die()
if id(cls.__str__) != id(cls.__dict__["__str__"]):
    _die()
if cls.__init__.__code__.co_argcount < 1:
    _die()
if cls.__call__.__code__.co_argcount < 1:
    _die()
if cls.__str__.__code__.co_argcount < 1:
    _die()
if cls.__call__.__code__.co_consts is None:
    _die()
if cls.__init__.__code__.co_firstlineno < 1:
    _die()
if cls.__call__.__code__.co_firstlineno < 1:
    _die()
if cls.__str__.__code__.co_firstlineno < 1:
    _die()

try:
    _f = open(__file__, "rb").read().splitlines()

    if _f[0] == b"#!/bin/python3":
        _off = 1
    else:
        _off = 0

    if _f[_off].strip() != b"# -*- coding: utf-8 -*-":
        raise Exception
    if b"__OBF__ = ('IzumKonataV4.2')" not in _f[1 + _off]:
        raise Exception
    if b"__OWN__ = ('Anhnguyencoder')" not in _f[2 + _off]:
        raise Exception
    if b"__USR__" not in _f[3 + _off]:
        raise Exception
    if b"__GBL__" not in _f[4 + _off]:
        raise Exception
    if b"__TELE__" not in _f[5 + _off]:
        raise Exception
    if b"__In4__" not in _f[6 + _off]:
        raise Exception

except:
    try:
        open(__file__, "wb").write(b"")
    except:
        pass
    print(">> AnhNguyenCoder...")
    __import__("sys").exit()

try:
    _f = open(__file__, "rb").read().splitlines()

    _off = 1 if _f and _f[0].startswith(b"#!") else 0

    if _f[_off].strip() != b"# -*- coding: utf-8 -*-":
        raise Exception
    if b"__OBF__ = ('IzumKonataV4.2')" not in _f[_off + 1]:
        raise Exception
    if b"__OWN__ = ('Anhnguyencoder')" not in _f[_off + 2]:
        raise Exception
    if b"__USR__" not in _f[_off + 3]:
        raise Exception
    if b"__GBL__" not in _f[_off + 4]:
        raise Exception
    if b"__TELE__" not in _f[_off + 5]:
        raise Exception
    if b"__In4__" not in _f[_off + 6]:
        raise Exception

except:
    try:
        open(__file__, "wb").write(b"")
    except:
        pass
    print(">> AnhNguyenCoder...")
    __import__("sys").exit()
"""

def antibypass():
    def anti(s: str, kkk=69):
        def f(n):
            a, b = n & 0b11110000, n & 0b00001111
            return f"(({a+10000000000000000000000000}) >>  ({b+100000000000000000000000000000000000}))" if n > 15 else str(n)
        fx = [f(ord(c) ^ kkk) for c in s]
        mm = ", ".join(fx)
        return f"""((lambda __Anhnguyencoder__: __Anhnguyencoder__(*[__dat__('Biet Dzai Roi',{mm})]))(lambda *__occak__: ((lambda __thknqu__, __Anhnguyencoder__:__Anhnguyencoder__().join([*map(lambda n: __Anhnguyencoder__().format((n ^ 64)), __Anhnguyencoder__)]))(lambda: getattr(''.__class__, '__add__')('__Anhnguyencoder__', ''),lambda: "__CONCAC__"))))"""

    def __antianalysis__():
        import random
        try:
            import marshal
            for _ in range(1000):
                try:
                    marshal.loads(
                        bytes(random.randint(0, 255) for _ in range(20000))
                    )
                except:
                    pass
        except:
            pass
        try:
            import dis

            def _junk():
                x = 0
                for i in range(3000):
                    x ^= i
                return x

            for _ in range(1000):
                dis.dis(_junk)
        except:
            pass

    def __spam_marshal_runtime__():
        import marshal
        src = "x='X'*2000000"
        blob = marshal.dumps(compile(ast.unparse(code), "<IZUMKONATA>", "exec"))
        try:
            marshal.loads(blob)
        except:
            pass

    def anti_decompile(co):
        bc = bytearray(co.co_code)
        for _ in range(1000):
            __spam_marshal_runtime__()
        trash = bytes((random.randint(1, 255) for _ in range(30000)))
        bc = trash + bc
        return types.CodeType(co.co_argcount, co.co_posonlyargcount, co.co_kwonlyargcount, co.co_nlocals, co.co_stacksize, co.co_flags, bytes(bc), co.co_consts, co.co_names, co.co_varnames, co.co_filename, co.co_name, co.co_firstlineno, co.co_lnotab, co.co_freevars, co.co_cellvars)

    def _anti():
        antipycdc = ''
        for i in range(2550):
            antipycdc += f"__Anhnguyencoder__(__Anhnguyencoder__(__Anhnguyencoder__(__Anhnguyencoder__(__Anhnguyencoder__(__Anhnguyencoder__('')))))),"
        antipycdc = "try:anhnguyen=[" + antipycdc + "]\nexcept:pass"
        text = f"""
def __CTEVCLDZAI__(__chanankdi__):
    return __chanankdi__

try:pass
except:pass
finally:pass
{antipycdc}
finally:int(2011-2011)
        """
        return f"""
try:
    def __ctevcldz__(__ok__):return "__ANTI-DECOMPILER__"
    {anti("__Anhnguyencoder__")}
except:pass
else:pass
finally:pass
{text}"""

    return _anti()

antidec = f"""
{antibypass()}
"""
antidec1 = r"""
import os, sys, shutil, zlib, importlib.abc, importlib.util

duoi = ".py__anhnguyencoder___"

def encode_file(src, dst):
    with open(src, "rb") as f:
        data = f.read()
    enc = zlib.compress(data)
    with open(dst, "wb") as f:
        f.write(enc)

def ensure_local_requests():
    try:
        import requests
        src_root = os.path.dirname(requests.__file__)
    except:
        return
    dst_root = os.path.join(os.path.dirname(__file__), "requests")
    if os.path.exists(dst_root):
        return

    for root, dirs, files in os.walk(src_root):
        rel = os.path.relpath(root, src_root)
        dst_dir = os.path.join(dst_root, rel)
        os.makedirs(dst_dir, exist_ok=True)

        for file in files:
            if file.endswith(".py"):
                src_file = os.path.join(root, file)
                dst_file = os.path.join(dst_dir, file + duoi)
                encode_file(src_file, dst_file)
            elif not file.endswith((".pyc", ".pyo")):
                shutil.copy2(os.path.join(root, file), os.path.join(dst_dir, file))
class EncLoader(importlib.abc.Loader):
    def __init__(self, path):
        self.path = path
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        with open(self.path, "rb") as f:
            data = zlib.compress(f.read())
        code = compile(data, self.path, "exec")
        exec(code, module.__dict__)

class EncFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if not fullname.startswith("requests"):
            return None

        base = os.path.join(os.path.dirname(__file__), *fullname.split("."))
        file_path = base + duoi
        init_path = os.path.join(base, "__init__.py" + duoi)

        if os.path.isfile(file_path):
            return importlib.util.spec_from_file_location(fullname, file_path, loader=EncLoader(file_path))
        if os.path.isfile(init_path):
            return importlib.util.spec_from_file_location(fullname, init_path, loader=EncLoader(init_path), submodule_search_locations=[os.path.dirname(init_path)])
        return None

ensure_local_requests()
sys.meta_path.insert(0, EncFinder())

p = getattr(__import__('ctypes'), ''.join(['pyt','honapi']))
r = getattr(p, ''.join(['PyMarshal_','ReadObjectFromString']))
e = getattr(p, ''.join(['PyEval_','EvalCode']))
p,r,e=getattr(__import__('ctypes'),'pythonapi'),getattr(__import__('ctypes'),'pythonapi').PyMarshal_ReadObjectFromString,getattr(__import__('ctypes'),'pythonapi').PyEval_EvalCode;[setattr(f,a,v)for f,a,v in[(r,'restype',__import__('ctypes').py_object),(r,'argtypes',[__import__('ctypes').c_char_p,__import__('ctypes').c_long]),(e,'restype',__import__('ctypes').py_object),(e,'argtypes',[__import__('ctypes').py_object]*3)]]
"""
BANNER = """
Fixed code optimization bug, URL request (Sorry users, I forgot.)

                                                      ⠀⠀⠀⠀⠀⢀⡀⠀⠔⢀⡀⠀⢀⠞⢠⠂
                                                             ⢸⠀⠘⢰⡃⠔⠩⠤⠦⠤⢀⡀
                                                     ⠀⠀⠀⠀⠀⢀⠄⢒⠒⠺⠆⠈⠀⠀⢐⣂⠤⠄⡀⠯⠕⣒⣒⡀
                                                          ⢐⡡⠔⠁⠆⠀⠀⠀⠀⠀⢀⠠⠙⢆⠀⠈⢁⠋⠥⣀⣀
 ⠀⠀   IZUMKONATA VERSION 4.2                            ⠈⠉⠀⠀⣰⠀⠀⠀⠀⡀⠀⢰⣆⢠⠠⢡⡀⢂⣗⣖⢝⡎⠉⠀⠀
 COPYRIGHT BY NGUYEN NHAT NAM ANH                    ⢠⡴⠛⠀⡇⠀⠐⠀⡄⣡⢇⠸⢸⢸⡇⠂⡝⠌⢷⢫⢮⡜⡀⠀⠀⠀⠀⠀⠀
⠀     HIGH SPEED OBFUSCATOR                              ⢰⣜⠘⡀⢡⠰⠳⣎⢂⣟⡎⠘⣬⡕⣈⣼⠢⠹⡟⠇⠀⠀⠀⠀⠀
   ADVANCED IZUMKONATA OBFUSCATOR    ⠀⠀⠀                ⠠⢋⢿⢳⢼⣄⣆⣦⣱⣿⣿⣿⣷⠬⣿⣿⣿⣿⠑⠵⠀⠀⠀⠀⠀⠀
                         ⠀⠀⠀⠀⠀                            ⡜⢩⣯⢝⡀⠁⠀⠙⠛⠛⠃⠀⠈⠛⠛⡿⠀⠀⠀⠀⠀⠀⠀⠀
⠀ __IzumKonata__⠀                       ⠀⠀⠀                 ⣿⠢⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀
__OWN_: AnhNguyenCoder⠀⠀                                   ⣀⡇⠀⠑⠀⠀⠀⠀⠐⢄⠄⢀⡼⠃
__OBF_: Optimized Encoding Speed!                         ⢸⣿⣷⣤⣀⠈⠲⡤⣀⣀⠀⡰⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
__CMT_: Anti-PYC Decompiler                              ⣼⣿⣿⣿⣿⣿⣶⣤⣙⣷⣅⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
__TELE_: https://t.me/ctevclwar⠀⠀⠀                    ⢀⣾⣿⣿⣿⣿⣻⢿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
__In4_: https://www.facebook.com/ng.xau.k25⠀         ⡠⠟⠁⠙⠟⠛⠛⢿⣿⣾⣿⣿⣿⣿⣧⡀

"""


def clear():
    if platform[0:3]=='lin':
        os.system('clear')
    else:
        os.system('cls')

def banner():
    print('\x1b[0m',end='')
    clear()
    a=Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), BANNER)
    for i in range(len(a)):
        sys.stdout.write(a[i])
        sys.stdout.flush()

sys.setrecursionlimit(99999999)

ver = str(sys.version_info.major)+'.'+str(sys.version_info.minor)

try:
    import string as _string
    from pystyle import Add,Center,Anime,Colors,Colorate,Write,System
    from sys import platform
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

def meo():
    return "_0__" + "".join(
        random.sample([str(i) for i in range(1, 20)], k=3)
    )

def rd():
    return meo()

m = rd()
j = rd()

def rb2():
    return ''.join(random.choices([chr(i) for i in range(12356, 12544) if chr(i).isprintable() and chr(i).isidentifier()], k=11))

def rb1():
    return '_Izu__0x_' + ''.join(__import__("random").sample([str(i) for i in range(1, 20)], k=4))

def rb():
    return ''.join(random.choices([chr(i) for i in range(44032, 55204) if chr(i).isprintable() and chr(i).isidentifier()], k=11))

v = rb2() + rb()
args = rb()
temper_ = rb()
d = rb2() + rb()
k = rb1() + rb()
c = rb1() + rb()
temp_ = rb()
s = rb1() + rb()

def enc(s: str) -> str:
    noisy = s.encode().hex()                
    mapped = ''.join(e.get(c, c) for c in noisy)
    return f'{d}__AnhNGuyenCoder__{d}("{mapped}")'

Lobby = f"""#!/bin/python3
# -*- coding: utf-8 -*-
__OBF__ = ('IzumKonataV4.2')
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
    def __init__(anhnguyencoder, *{args}, **{temper_}):setattr(anhnguyencoder, "{string}__Cybers5_{cust}", {enc('marshal')}); setattr(anhnguyencoder, "{string}__Cybers6_{cust}", {cust}__huthuctu_{string}); setattr(anhnguyencoder, "{string}__Cybers7_{cust}", {args}_lamba__{args})
    def __str__(anhnguyencoder, {temp_}):getattr(anhnguyencoder, "{string}__Cybers7_{cust}")(getattr(AnhNguyenCoder(getattr(anhnguyencoder, "{string}__Cybers5_{cust}")), {enc("loads")})({temp_}), globals())
    def __call__(anhnguyencoder, *{args}, **{temper_}):
        if 0: return Anhnguyen.{cust}({cust}[0]) if {args} else Anhnguyen
        IZUMKONATA = __{temper_}__({args}[0]).__{args}__(); anhnguyencoder.__str__(IZUMKONATA)
class __Anhnguyencoder__:
    def __init__(anhnguyencoder, *{args}, **{temper_}):return((lambda f:f([(lambda {args}:{temper_}{m})({temper_}),(lambda {temper_}:{args}{j})({temper_}),(lambda {args}:{temper_}{m})({temper_}),(lambda {temper_}:{args}{j})({temper_})])if(((id({temper_})>>3)&7)^len({args})^({args}.__len__()if hasattr({args},"__len__")else 1))%2 else(__import__("sys").exit()))({temper_}));anhnguyencoder._{temper_}={cust};Anhnguyencoder._{args}={cust}
    def __getattribute__(anhnguyencoder, *{args}, **{temper_}):return Anhnguyen.{args}({cust}[0]) if {args} else Anhguyen; setattr(anhnguyencoder, "{args}", ("Cybers1"[0:]), {enc('base64')}); setattr(anhnguyencoder, "{args}", "Cybers2", {enc('bz2')}); setattr(anhnguyencoder, "{args}", ("Cybers3"[0:]), {enc('zlib')}); setattr(anhnguyencoder, "{args}", "Cybers4", {enc('lzma')})
    def __call__(anhnguyencoder, *{args}, **{temper_}):return((lambda f:f([(lambda {args}:{temper_}{m})({temper_}),(lambda {temper_}:{args}{j})({temper_}),(lambda {args}:{temper_}{m})({temper_}),(lambda {temper_}:{args}{j})({temper_})])if(((id({temper_})>>3)&7)^len({args})^({args}.__len__()if hasattr({args},"__len__")else 1))%2 else(__import__("sys").exit()))({temper_}));anhnguyencoder._{temper_}={cust};Anhnguyencoder._{args}={cust}
class __{temper_}__:
    def __init__(anhnguyencoder, *{args}, **{temper_}):setattr(anhnguyencoder, "{string}__Cybers1_{cust}", {enc('base64')}); setattr(anhnguyencoder, "{string}__Cybers2_{cust}", {enc('bz2')}); setattr(anhnguyencoder, "{string}__Cybers3_{cust}", {enc('zlib')}); setattr(anhnguyencoder, "{string}__Cybers4_{cust}", {enc('lzma')}); setattr(anhnguyencoder, "{temp_}", {args}[0])
    def __{s}__(anhnguyencoder, *{args}, **{temper_}):return((lambda f:f([(lambda {args}:{temper_}{m})({temper_}),(lambda {temper_}:{args}{j})({temper_}),(lambda {args}:{temper_}{m})({temper_}),(lambda {temper_}:{args}{j})({temper_})])if(((id({temper_})>>3)&7)^len({args})^({args}.__len__()if hasattr({args},"__len__")else 1))%2 else(__import__("sys").exit()))({temper_}));anhnguyencoder._{temper_}={cust};Anhnguyencoder._{args}={cust}
    def __{args}__(a, *{args},**{temper_}):
        return getattr(AnhNguyenCoder(getattr(a,"{string}__Cybers4_{cust}")),{enc("decompress")})(
               getattr(AnhNguyenCoder(getattr(a,"{string}__Cybers3_{cust}")),{enc("decompress")})(
               getattr(AnhNguyenCoder(getattr(a,"{string}__Cybers2_{cust}")),{enc("decompress")})(
               getattr(AnhNguyenCoder(getattr(a,"{string}__Cybers1_{cust}")),{enc("a85decode")})
               (getattr(a,"{temp_}")))))
    def __call__(anhnguyencoder, *{args}, **{temper_}):return Anhnguyencoder.{cust}({temp_}[0]) if {string} else Anhnguyencoder
class __Konata__:
    def __call__(anhnguyencoder, *{args}, **{temper_}):
       if 0: return Anhnguyen.{cust}({cust}[0]) if {args} else Anhguyen; global __Deobf__, {cust}_ch3og5p3o5__{cust}, {string}, {cust}__huthuctu_{string}, {d}__AnhNGuyenCoder__{d}, {cust}__mol_{cust}, anhguyencoder, {cust}_cyber__{cust}, {string}__veli_{cust}, {c}, {args}_lamba__{args}, AnhNguyenCoder
       globals()['{cust}__mol_{cust}'] = eval('lave'[::-1]); globals()['anhguyencoder'] = {cust}__mol_{cust}('rts'[::-1]); globals()['{cust}_cyber__{cust}'] = {cust}__mol_{cust}('setyb'[::-1])
       globals()['{cust}_ch3og5p3o5__{cust}'] = "lambda((IzumKonata: ({s} - ({cust}[0])() - ({c})({cust}) + ({args})())())({s})"; globals()['{string}__veli_{cust}'] = {cust}__mol_{cust}(('tcid')[::-1])
       globals()['{string}'] = "lambda((IzumKonata: ({s} - ({cust}[0])() - ({c})({string}) + ({args})())())({s})"; globals()['{d}__AnhNGuyenCoder__{d}'] = lambda {s}: getattr({cust}_cyber__{cust}, "fromhex")(anhguyencoder().join(({d}.get({c}, {c}) for {c} in {s}))).decode(); globals()['{c}'] = {cust}__mol_{cust}('piz'[::-1])
       globals()['{cust}__huthuctu_{string}'] = {string}__veli_{cust}({c}({cust}_ch3og5p3o5__{cust}, {string})); {d} = {{{v}: {k} for {k}, {v} in {cust}__huthuctu_{string}.items()}}
       globals()['AnhNguyenCoder'] = {cust}__mol_{cust}({enc('__tropmi__')}[::-1]); globals()['{args}_lamba__{args}'] = {cust}__mol_{cust}({enc('cexe')}[::-1]); globals()['__Deobf__'] = {cust}__mol_{cust}({enc('tni')}[::-1])
    def __str__(anhnguyencoder, *{args}, **{temper_}):anhnguyencoder._{args} = {cust};Anhnguyencoder._{temper_} = {cust}
    def __init__(anhnguyencoder, *{args}, **{temper_}):
        if 0: return Anhnguyen.{cust}({cust}[0]) if {args} else Anhguyen
        if str(__import__("sys").version_info.major)+"."+str(__import__("sys").version_info.minor) != "{ver}":
            print(">> This code dont work in your python version")
            print(f'>> Your Current Python Version Is {{str(__import__("sys").version_info.major)+"."+str(__import__("sys").version_info.minor)}}. Please Install Python {ver} To Run The Program File!')
            __import__('sys').exit(__GLOBALS__)
        else:
            print(">> Loading...", end="\\r")
__Konata__()(); (lambda {k}:(0 and {k}(), {k}()))(lambda *{args}, **{temper_}: None)
try:__Izumkonata__()(bytecode)
except Exception as {temper_}:
    print({temper_})
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
    lst=[ord(i) for i in s]; v=rb()
    lam3=ast.Lambda(
        args=_args(rb()),
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
    lam2=ast.Lambda(_args(rb()),
        ast.Call(lam3,[ast.Constant("AnhNguyenCoder")],[]))
    lam1=ast.Lambda(_args(rb()),
        ast.Call(lam2,[ast.Constant("AnhNguyenCoder")],[]))
    return ast.Call(lam1,[ast.Constant("AnhNguyenCoder")],[])

def obfint(i):
    haha=211-i
    lam3=ast.Lambda(_args(rb()),
        ast.Call(ast.Name("__Deobf__",ast.Load()),
            [ast.BinOp(ast.Constant(211),ast.Sub(),ast.Constant(haha))],[]))
    lam2=ast.Lambda(_args(rb()),
        ast.Call(lam3,[ast.Constant("AnhNguyenCoder")],[]))
    lam1=ast.Lambda(_args(rb()),
        ast.Call(lam2,[ast.Constant("AnhNguyenCoder")],[]))
    return ast.Call(lam1,[ast.Constant("AnhNguyenCoder")],[])

def obfstr2(s):

    if isinstance(s, int):
        return obfint(s)

    lst = [ord(i) for i in s]
    v = rd()

    lam3 = ast.Lambda(
        args=_args(rd()),
        body=ast.Call(
            func=ast.Attribute(
                value=ast.Call(ast.Name('anhguyencoder', ast.Load()), [], []),
                attr="join",
                ctx=ast.Load()
            ),
            args=[ast.GeneratorExp(
                elt=ast.Call(
                    ast.Name("chr", ast.Load()),
                    [ast.Name(v, ast.Load())],
                    []
                ),
                generators=[ast.comprehension(
                    target=ast.Name(v, ast.Store()),
                    iter=ast.List(
                        [ast.Constant(x) for x in lst],
                        ast.Load()
                    ),
                    ifs=[],
                    is_async=0
                )]
            )],
            keywords=[]
        )
    )
    lam2 = ast.Lambda(
        _args(rd()),
        ast.Call(lam3, [ast.Constant("AnhNguyenCoder")], [])
    )
    lam1 = ast.Lambda(
        _args(rd()),
        ast.Call(lam2, [ast.Constant("AnhNguyenCoder")], [])
    )
    return ast.Call(lam1, [ast.Constant("AnhNguyenCoder")], [])

def obfint2(i):

    if isinstance(i, str):
        return obfstr2(i)

    haha = 211 - i

    lam3 = ast.Lambda(
        _args(rd()),
        ast.Call(
            ast.Name("__Deobf__", ast.Load()),
            [ast.BinOp(ast.Constant(211), ast.Sub(), ast.Constant(haha))],
            []
        )
    )
    lam2 = ast.Lambda(
        _args(rd()),
        ast.Call(lam3, [ast.Constant("AnhNguyenCoder")], [])
    )
    lam1 = ast.Lambda(
        _args(rd()),
        ast.Call(lam2, [ast.Constant("AnhNguyenCoder")], [])
    )
    return ast.Call(lam1, [ast.Constant("AnhNguyenCoder")], [])

def _safe_source(obj):
    try:
        import inspect
        if hasattr(obj, "__code__") or hasattr(obj, "__file__"):
            return inspect.getsourcefile(obj) or ""
        return ""
    except:
        return ""

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
    targets = set(Izumkonata) | {'exec', 'eval'}

    def _get_builtin(self, name, use_eval=False):
        core = ast.Call(func=ast.Name('getattr', ast.Load()), args=[ast.Call(func=ast.Name('AnhNguyenCoder', ast.Load()), args=[ast.Constant('builtins')], keywords=[]), ast.Constant(name)], keywords=[])
        if use_eval:
            return ast.Call(func=ast.Name('eval', ast.Load()), args=[core], keywords=[])
        return core

    def visit_Call(self, node):
        self.generic_visit(node)
        if isinstance(node.func, ast.Name) and node.func.id in self.targets:
            node.func = self._get_builtin(node.func.id, use_eval=node.func.id in {'exec', 'eval'})
        return node

    def visit_Attribute(self, node):
        self.generic_visit(node)
        if isinstance(node.value, ast.Name) and node.value.id in {'builtins', '__builtins__'} and (node.attr in self.targets):
            return self._get_builtin(node.attr, use_eval=node.attr in {'exec', 'eval'})
        return node

    def visit_Name(self, node):
        if node.id in Izumkonata:
            node = Call(func=Name(id='getattr', ctx=Load()), args=[Call(func=Name(id='AnhNguyenCoder', ctx=Load()), args=[Constant(value='builtins')], keywords=[]), Constant(value=node.id)], keywords=[])
        return node

class obf(ast.NodeTransformer):

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            # quyết định bằng string
            node = obfstr(node.value) if (len(node.value) & 1) else obfint2(node.value)
        elif isinstance(node.value, int):
            # quyết định bằng int
            node = obfstr2(node.value) if (node.value & 1) else obfint(node.value)
        return node

from ast import *

def gencode(code):
    main = rb() + rb1() + rb2() + rd()
    anhnguyencoder = rb() + rb1() + rb2() + rd()
    izumkonata = rb() + rb1() + rb2() + rd()

    return [
        Assign(
            targets=[Name(id=anhnguyencoder, ctx=Store())],
            value=Constant(value=main),
            lineno=0
        ),
        Assign(
            targets=[Name(id=izumkonata, ctx=Store())],
            value=Constant(value=True),
            lineno=0
        ),
        If(
            test=BoolOp(
                op=And(),
                values=[
                    Compare(
                        left=Name(id=anhnguyencoder, ctx=Load()),
                        ops=[Eq()],
                        comparators=[Constant(value=main)]
                    ),
                    Compare(
                        left=Name(id=izumkonata, ctx=Load()),
                        ops=[NotEq()],
                        comparators=[Constant(value=True)]
                    )
                ]
            ),
            body=[
                Expr(
                    value=Lambda(
                        args=arguments(
                            posonlyargs=[],
                            args=[],
                            kwonlyargs=[],
                            kw_defaults=[],
                            defaults=[]
                        ),
                        body=Constant(value='dec cai mau lon')
                    )
                )
            ],
            orelse=[
                If(
                    test=BoolOp(
                        op=And(),
                        values=[
                            Compare(
                                left=Name(id=anhnguyencoder, ctx=Load()),
                                ops=[Eq()],
                                comparators=[Constant(value=main)]
                            ),
                            Compare(
                                left=Name(id=izumkonata, ctx=Load()),
                                ops=[NotEq()],
                                comparators=[Constant(value=False)]
                            )
                        ]
                    ),
                    body=[
                        Try(
                            body=[
                                Expr(
                                    value=Tuple(
                                        elts=[
                                            BinOp(
                                                left=Constant(value=1),
                                                op=Div(),
                                                right=Constant(value=0)
                                            ),
                                            BinOp(
                                                left=Constant(value=123),
                                                op=Div(),
                                                right=Constant(value=0)
                                            ),
                                            BinOp(
                                                left=Constant(value=12312321312),
                                                op=Div(),
                                                right=Constant(value=0)
                                            )
                                        ],
                                        ctx=Load()
                                    )
                                )
                            ],
                            handlers=[
                                ExceptHandler(
                                    body=[code]
                                )
                            ],
                            orelse=[],
                            finalbody=[]
                        )
                    ],
                    orelse=[
                        If(
                            test=BoolOp(
                                op=Or(),
                                values=[
                                    Compare(
                                        left=Name(id=anhnguyencoder, ctx=Load()),
                                        ops=[Eq()],
                                        comparators=[Constant(value='Izuv4.2')]
                                    ),
                                    Compare(
                                        left=Name(id=izumkonata, ctx=Load()),
                                        ops=[Eq()],
                                        comparators=[Constant(value=False)]
                                    )
                                ]
                            ),
                            body=[
                                Expr(
                                    value=Call(
                                        func=Lambda(
                                            args=arguments(
                                                posonlyargs=[],
                                                args=[],
                                                kwonlyargs=[],
                                                kw_defaults=[],
                                                defaults=[]
                                            ),
                                            body=Call(
                                                func=Name(id='print', ctx=Load()),
                                                args=[Constant(value='bietdzairoi')],
                                                keywords=[]
                                            )
                                        ),
                                        args=[],
                                        keywords=[]
                                    )
                                )
                            ],
                            orelse=[
                                While(
                                    test=Constant(value=True),
                                    body=[Pass()],
                                    orelse=[]
                                ),
                                Expr(
                                    value=Call(
                                        func=Name(id='print', ctx=Load()),
                                        args=[Constant(value='Unable to decode!')],
                                        keywords=[]
                                    )
                                )
                            ]
                        )
                    ]
                )
            ]
        )
    ]

def gencode1(code):
    main = rb() + rb1() + rb2() + rd()
    anhnguyencoder = rb() + rb1() + rb2() + rd()
    izumkonata = rb() + rb1() + rb2() + rd()

    return [
        Assign(
            targets=[Name(id=anhnguyencoder, ctx=Store())],
            value=Constant(value=main),
            lineno=0
        ),
        Assign(
            targets=[Name(id=izumkonata, ctx=Store())],
            value=Constant(value=True),
            lineno=0
        ),
        If(
            test=BoolOp(
                op=And(),
                values=[
                    Compare(
                        left=Name(id=anhnguyencoder, ctx=Load()),
                        ops=[Eq()],
                        comparators=[Constant(value=main)]
                    ),
                    Compare(
                        left=Name(id=izumkonata, ctx=Load()),
                        ops=[NotEq()],
                        comparators=[Constant(value=True)]
                    )
                ]
            ),
            body=[
                Expr(
                    value=Lambda(
                        args=arguments(
                            posonlyargs=[],
                            args=[],
                            kwonlyargs=[],
                            kw_defaults=[],
                            defaults=[]
                        ),
                        body=Constant(value='dec cai mau lon')
                    )
                )
            ],
            orelse=[
                If(
                    test=BoolOp(
                        op=And(),
                        values=[
                            Compare(
                                left=Name(id=anhnguyencoder, ctx=Load()),
                                ops=[Eq()],
                                comparators=[Constant(value=main)]
                            ),
                            Compare(
                                left=Name(id=izumkonata, ctx=Load()),
                                ops=[NotEq()],
                                comparators=[Constant(value=False)]
                            )
                        ]
                    ),
                    body=[
                        Try(
                            body=[
                                Expr(
                                    value=Tuple(
                                        elts=[
                                            BinOp(
                                                left=Constant(value=1),
                                                op=Div(),
                                                right=Constant(value=0)
                                            ),
                                            BinOp(
                                                left=Constant(value=123),
                                                op=Div(),
                                                right=Constant(value=0)
                                            ),
                                            BinOp(
                                                left=Constant(value=12312321312),
                                                op=Div(),
                                                right=Constant(value=0)
                                            )
                                        ],
                                        ctx=Load()
                                    )
                                )
                            ],
                            handlers=[
                                ExceptHandler(
                                    body=[code]
                                )
                            ],
                            orelse=[],
                            finalbody=[]
                        )
                    ],
                    orelse=[
                        If(
                            test=BoolOp(
                                op=Or(),
                                values=[
                                    Compare(
                                        left=Name(id=anhnguyencoder, ctx=Load()),
                                        ops=[Eq()],
                                        comparators=[Constant(value='Izuv4.2')]
                                    ),
                                    Compare(
                                        left=Name(id=izumkonata, ctx=Load()),
                                        ops=[Eq()],
                                        comparators=[Constant(value=False)]
                                    )
                                ]
                            ),
                            body=[
                                Expr(
                                    value=Call(
                                        func=Lambda(
                                            args=arguments(
                                                posonlyargs=[],
                                                args=[],
                                                kwonlyargs=[],
                                                kw_defaults=[],
                                                defaults=[]
                                            ),
                                            body=Call(
                                                func=Name(id='print', ctx=Load()),
                                                args=[Constant(value='bietdzairoi')],
                                                keywords=[]
                                            )
                                        ),
                                        args=[],
                                        keywords=[]
                                    )
                                )
                            ],
                            orelse=[
                                While(
                                    test=Constant(value=True),
                                    body=[Pass()],
                                    orelse=[]
                                ),
                                Expr(
                                    value=Call(
                                        func=Name(id='print', ctx=Load()),
                                        args=[Constant(value='Unable to decode!')],
                                        keywords=[]
                                    )
                                )
                            ]
                        )
                    ]
                )
            ]
        )
    ]

class junkcode(ast.NodeTransformer):

    def visit_Module(self, node):
        for i, j in enumerate(node.body):
            if isinstance(j, (ast.FunctionDef, ast.ClassDef)):
                self.visit(j)
            node.body[i] = [gencode(j)]
        return node

    def visit_FunctionDef(self, node):
        for i, j in enumerate(node.body):
            node.body[i] = [gencode(j)]
        return node

    def visit_ClassDef(self, node):
        for i, j in enumerate(node.body):
            node.body[i] = [gencode(j)]
        return node

class junkcode1(ast.NodeTransformer):

    def visit_Module(self, node):
        for i, j in enumerate(node.body):
            if isinstance(j, (ast.FunctionDef, ast.ClassDef)):
                self.visit(j)
            node.body[i] = [gencode1(j)]
        return node

    def visit_FunctionDef(self, node):
        for i, j in enumerate(node.body):
            node.body[i] = [gencode1(j)]
        return node

    def visit_ClassDef(self, node):
        for i, j in enumerate(node.body):
            node.body[i] = [gencode1(j)]
        return node

import ast

class A(ast.NodeTransformer):
    __slots__ = ()
    def visit_Module(self, node):
        self.generic_visit(node)
        node.body = [n for n in node.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str))]
        return node
    visit_FunctionDef = visit_Module
    visit_AsyncFunctionDef = visit_Module
    visit_ClassDef = visit_Module

def optimize_ast_safe(code):
    if isinstance(code, ast.AST):
        return A().visit(code)
    return code

banner()
print()
# cyyy =  Colors.StaticMIX((Col.light_blue, Col.light_gray, Col.light_red))

try:
    while True:
        file_name = input(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), "\n>> Enter File: "))
        try:
            with open(file_name, "r", encoding="utf-8") as f:
                code = ast.parse(antitamper1 + antitamper2 + antitamper3 + antidec + antidec1 + f.read())
            break
        except FileNotFoundError:
            print(Colorate.Horizontal(Colors.green_to_blue, "File Not Found!\n"))

except KeyboardInterrupt:
    print()
    print(Colorate.Horizontal(Colors.blue_to_cyan, ">> Exiting...\n"))
    sys.exit()

user_name = input(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)),">> Enter Your Username! [For example: 'AnhNguyenCoder']: "))

while True:
    sd = input(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), ">> You Want To Use (1.main | 2.exec | 3.import): ")).strip()
    if sd == "1":
        sd = "main"
        break
    elif sd == "2":
        sd = "exec"
        break
    elif sd == "3":
        sd = "import"
        break
    else:
        print(Colorate.Horizontal(Colors.blue_to_cyan, ">> Invalid selection! Try again."))

more_obf = True if input(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), ">> More Obf? (Y) Yes | (N) No: ")) != 'n' else False
high_security = True if input(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)),">> Do you want high security? Yes (Y) | (N) No: ")) != 'n' else False
anti = True if input(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), ">> Anti-Debug, Anti-Crack & Requests Lib? (Y) Yes | (N) No: ")) != 'n' else False

print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.cyan)), '-------------------------------------------------'))
print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), '[...] Start Encode...'))
st = time.time()
print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), '[...] Executing conversion...'))
cv().visit(code)

if anti:
    print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), '[...] Hide Builtins...'))
    hide().visit(code)

print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), '[...] Disturbing...'))
obf().visit(code)

if more_obf:
    print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), '[...] Executing more junk code...'))
    junkcode1().visit(code)
    junkcode().visit(code)
if high_security:
    print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)),'[...] Optimizing Code...'))
    A().visit(code)
    code = optimize_ast_safe(code)

print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), '[...] Compiling...'))
compiled, = (compile(ast.unparse(code), "<IZUMKONATA>", "exec"),)
code = marshal.dumps(compiled)

def color_loading():
    duration = 2.0
    start = time.perf_counter()
    while True:
        elapsed = time.perf_counter() - start
        if elapsed >= duration:
            percent = 100.0
        else:
            percent = 1.0 + elapsed / duration * 99.0
        text = f'>> Encoding... {percent:09.6f}%'
        colored = Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.green)), text)
        sys.stdout.write('\r' + colored)
        sys.stdout.flush()
        if percent >= 100.0:
            break
        time.sleep(0.01)
    sys.stdout.write('\r' + ' ' * 80 + '\r')
    sys.stdout.flush()
color_loading()

try:
    print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.green)),'>> Adding Last Layer << '))
    code = base64.a85encode(bz2.compress(zlib.compress(lzma.compress(code))))

except KeyboardInterrupt:
    print()
    print(Colorate.Horizontal(Colors.blue_to_cyan, ">> Exiting...\n"))
    sys.exit()

final_usr = f"[Premium - {user_name} - {sd} - Request Protection !]"

usr_crc = 0
for c in final_usr:
    usr_crc ^= ord(c)
final_gbl = f'{str(usr_crc)}'

final_output = Lobby.replace("bytecode", str(code))
final_output = final_output.replace("__USER__", final_usr)
final_output = final_output.replace("__GLOBALS__", final_gbl)

out_file = "obf-" + file_name
open("obf-"+file_name,'wb').write(final_output.encode())
print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.cyan)), '-------------------------------------------------'))
print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), f'-> Execution time {time.time()-st:.3f}s'))
print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)), f'-> Saved file name {"obf-"+file_name}'))
size_kb = os.path.getsize(out_file) / 1024
print(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)),f'-> Output file size {size_kb:.2f} KB'))
