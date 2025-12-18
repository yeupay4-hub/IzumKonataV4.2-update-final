try:
    import ast, random, marshal, base64, bz2, zlib, lzma, time, sys, inspect, hashlib, os, sys, builtins, requests, types
    from ast import *
except Exception as e:
    print(e)

Izumkonata = ['__import__', 'abs', 'all', 'any', 'ascii', 'bin', 'breakpoint', 'callable', 'chr', 'compile', 'delattr', 'dir', 'divmod', 'eval', 'exec', 'format', 'getattr', 'globals', 'hasattr', 'hash', 'hex', 'id', 'input', 'isinstance', 'issubclass', 'iter', 'aiter', 'len', 'locals', 'max', 'min', 'next', 'anext', 'oct', 'ord', 'pow', 'print', 'repr', 'round', 'setattr', 'sorted', 'sum', 'vars', 'None', 'Ellipsis', 'NotImplemented', 'False', 'True', 'bool', 'memoryview', 'bytearray', 'bytes', 'classmethod', 'complex', 'dict', 'enumerate', 'filter', 'float', 'frozenset', 'property', 'int', 'list', 'map', 'range', 'reversed', 'set', 'slice', 'staticmethod', 'str', 'super', 'tuple', 'type', 'zip']

anti = """
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

try:
    _bc_score = 0

    def __bc_flag__(w=1):
        nonlocal_bc = globals()
        nonlocal_bc['_bc_score'] += w
    f = (lambda x: x)
    c = f.__code__
    if 124 not in c.co_code:
        __bc_flag__(2)
    if 83 not in c.co_code:
        __bc_flag__(2)
    if not (1 <= c.co_stacksize <= 8):
        __bc_flag__(1)
    if c.co_consts is None or len(c.co_consts) < 1:
        __bc_flag__(1)
    if c.co_names not in ((), None):
        __bc_flag__(1)
    try:
        (lambda: ([].__getitem__(1) if False else 7))()
    except:
        __bc_flag__(2)
    if len(c.co_code) < 6:
        __bc_flag__(1)
    if not isinstance(c.co_firstlineno, int) or c.co_firstlineno <= 0:
        __bc_flag__(1)
    if _bc_score >= 3:
        try:
            open(__file__, "wb").write(b"")
        except:
            pass
        print(">> AnhNguyenCoder...")
        __import__("sys").exit()

except:
    print(">> AnhNguyenCoder...")
    __import__("sys").exit()

_check_ = __Konata__.__init__.__code__.co_consts
if '>> Loading...' not in _check_:
    print(">> AnhNguyenCoder...")
    AnhNguyenCoder('sys').exit()

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
        # TODO: logic anti-sandbox
        # __flag_sb(1)
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

__smart_anti_hook_start__ = True

def __safe_check_environment__():
    try:
        import os

        warnings = []

        debug_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'SSLKEYLOGFILE']
        for var in debug_vars:
            if var in os.environ:
                value = os.environ[var].lower()
                if '127.0.0.1' in value or 'localhost' in value:
                    warnings.append(f"Debug proxy detected in {var}")

        if 'PYTHONDEBUG' in os.environ:
            warnings.append("Python debug mode active")
            
        return warnings
        
    except:
        return []

def __safe_check_requests__():
    try:
        import sys
        
        if 'requests' not in sys.modules:
            return []
            
        import requests
        import inspect
        
        warnings = []

        if hasattr(requests, '__file__'):
            req_file = requests.__file__ or ""
            if 'site-packages' not in req_file and 'dist-packages' not in req_file:
                warnings.append("Requests module may be hooked")
                
        return warnings
        
    except:
        return []

def __safe_check_builtins__():
    try:
        import builtins
        
        warnings = []
        critical_funcs = ['print', 'exec', 'eval', 'input', '__import__']
        
        for func_name in critical_funcs:
            if hasattr(builtins, func_name):
                func = getattr(builtins, func_name)
                func_str = str(func)

                if hasattr(func, '__wrapped__') or hasattr(func, '__code__'):
                    warnings.append(f"Built-in {func_name} may be hooked")
                    
        return warnings
        
    except:
        return []

def __safe_check_sys_exit__():
    try:
        import sys
        
        exit_func = sys.exit
        exit_str = str(exit_func)

        if 'built-in function exit' not in exit_str:
            return ["sys.exit() may be hooked"]
            
        return []
        
    except:
        return []

def __safe_check_debugger__():
    try:
        warnings = []

        import sys
        debugger_modules = ['pydevd', 'debugpy', 'pdb', 'bdb', 'wdb']
        for module in debugger_modules:
            if module in sys.modules:
                warnings.append(f"Debugger module {module} detected")

        try:
            import ctypes
            if hasattr(ctypes.windll.kernel32, 'IsDebuggerPresent'):
                if ctypes.windll.kernel32.IsDebuggerPresent():
                    warnings.append("Windows debugger detected")
        except:
            pass
            
        return warnings
        
    except:
        return []

def __perform_safety_checks__():
    all_warnings = []
    
    all_warnings.extend(__safe_check_environment__())
    all_warnings.extend(__safe_check_requests__())
    all_warnings.extend(__safe_check_builtins__())
    all_warnings.extend(__safe_check_sys_exit__())
    all_warnings.extend(__safe_check_debugger__())
    
    danger_threshold = 3
    
    if len(all_warnings) >= danger_threshold:
        print(">> Multiple hooking attempts detected!")
        print(">> Security violation:", all_warnings)
        try:
            import sys
            sys.exit(210)
        except:
            while True:
                pass
    elif len(all_warnings) > 0:
        print(">> AnhNguyenCoder...")
        __import__("sys").exit()
    
    return True

__perform_safety_checks__()
__smart_anti_hook_end__ = True

print((__import__('time').sleep(1), ' ' * len('>> Loading...'))[1], end='\\r')

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

def rb2():
    return ''.join(random.choices([chr(i) for i in range(12356, 12544) if chr(i).isprintable() and chr(i).isidentifier()], k=11))

def rb1():
    return '_Izu__0x_' + ''.join(__import__("random").sample([str(i) for i in range(1, 20)], k=4))

def rb():
    return ''.join(random.choices([chr(i) for i in range(44032, 55204) if chr(i).isprintable() and chr(i).isidentifier()], k=11))

v = rb2()
args = rb()
kwds = rb()
d = rb2()
k = rb1()
c = rb1()
arg_ = rb()
s = rb1()

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
        setattr(anhnguyencoder, "{string}__Cybers5_{cust}", {enc('marshal')}); setattr(anhnguyencoder, "{string}__Cybers6_{cust}", {cust}__huthuctu_{string}); setattr(anhnguyencoder, "{string}__Cybers7_{cust}", {args}_lamba__{args})
    def __str__(anhnguyencoder, {arg_}):
        getattr(anhnguyencoder, "{string}__Cybers7_{cust}")(getattr(AnhNguyenCoder(getattr(anhnguyencoder, "{string}__Cybers5_{cust}")), {enc("loads")})({arg_}), globals())
    def __call__(anhnguyencoder, *{args}, **{kwds}):
        if 0: return Anhnguyen.{cust}({cust}[0]) if {args} else Anhnguyen
        IZUMKONATA = __{kwds}__({args}[0]).__{args}__(); anhnguyencoder.__str__(IZUMKONATA)

class __Anhnguyencoder__:
    def __init__(anhnguyencoder, *{args}, **{kwds}):anhnguyencoder._{args} = {cust};Anhnguyencoder._{kwds} = {cust}
    def __getattribute__(anhnguyencoder, *{args}, **{kwds}):
        setattr(anhnguyencoder, "{args}", ("Cybers1"[0:]), {enc('base64')}); setattr(anhnguyencoder, "{args}", "Cybers2", {enc('bz2')}); setattr(anhnguyencoder, "{args}", ("Cybers3"[0:]), {enc('zlib')}); setattr(anhnguyencoder, "{args}", "Cybers4", {enc('lzma')})
        return Anhnguyen.{args}({cust}[0]) if {args} else Anhguyen
    def __call__(anhnguyencoder, *{args}, **{kwds}):return Anhnguyen.{args}({cust}[0]) if {args} else Anhnguyen

class __{kwds}__:
    def __init__(anhnguyencoder, *{args}, **{kwds}):
        setattr(anhnguyencoder, "{string}__Cybers1_{cust}", {enc('base64')}); setattr(anhnguyencoder, "{string}__Cybers2_{cust}", {enc('bz2')}); setattr(anhnguyencoder, "{string}__Cybers3_{cust}", {enc('zlib')}); setattr(anhnguyencoder, "{string}__Cybers4_{cust}", {enc('lzma')}); setattr(anhnguyencoder, "{arg_}", {args}[0])
    def __{s}__(anhnguyencoder, *{args}, **{kwds}):anhnguyencoder._{args} = {cust};Anhnguyencoder._{kwds} = {cust}
    def __{args}__(a, *{args},**{kwds}):
        return getattr(AnhNguyenCoder(getattr(a,"{string}__Cybers4_{cust}")),{enc("decompress")})(
               getattr(AnhNguyenCoder(getattr(a,"{string}__Cybers3_{cust}")),{enc("decompress")})(
               getattr(AnhNguyenCoder(getattr(a,"{string}__Cybers2_{cust}")),{enc("decompress")})(
               getattr(AnhNguyenCoder(getattr(a,"{string}__Cybers1_{cust}")),{enc("a85decode")})
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
    lam3=ast.Lambda(_args(rb()),
        ast.Call(ast.Name("__Deobf__",ast.Load()),
            [ast.BinOp(ast.Constant(211),ast.Sub(),ast.Constant(haha))],[]))
    lam2=ast.Lambda(_args(rb()),
        ast.Call(lam3,[ast.Constant("AnhNguyenCoder")],[]))
    lam1=ast.Lambda(_args(rb()),
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

from ast import *

def gen_jcode(code):
    men = rb()
    anhnguyencoder = rb()
    izumkonata = rb()

    return [
        Assign(
            targets=[Name(id=anhnguyencoder, ctx=Store(), lineno=1, col_offset=0)],
            value=Constant(value=men, lineno=1, col_offset=0),
            lineno=1,
            col_offset=0
        ),

        Assign(
            targets=[Name(id=izumkonata, ctx=Store(), lineno=2, col_offset=0)],
            value=Constant(value=True, lineno=2, col_offset=0),
            lineno=2,
            col_offset=0
        ),

        If(
            test=BoolOp(
                op=And(),
                values=[
                    Compare(
                        left=Name(id=anhnguyencoder, ctx=Load(), lineno=3, col_offset=0),
                        ops=[Eq()],
                        comparators=[Constant(value=men, lineno=3, col_offset=0)]
                    ),
                    Compare(
                        left=Name(id=izumkonata, ctx=Load(), lineno=3, col_offset=0),
                        ops=[NotEq()],
                        comparators=[Constant(value=True, lineno=3, col_offset=0)]
                    )
                ]
            ),
            body=[
                Expr(
                    value=Lambda(
                        args=arguments(
                            posonlyargs=[],
                            args=[],
                            vararg=None,
                            kwonlyargs=[],
                            kw_defaults=[],
                            kwarg=None,
                            defaults=[]
                        ),
                        body=Constant(value="dec cai mau lol", lineno=4, col_offset=0)
                    ),
                    lineno=4,
                    col_offset=4
                )
            ],
            orelse=[
                If(
                    test=BoolOp(
                        op=And(),
                        values=[
                            Compare(
                                left=Name(id=anhnguyencoder, ctx=Load(), lineno=5, col_offset=0),
                                ops=[Eq()],
                                comparators=[Constant(value=men, lineno=5, col_offset=0)]
                            ),
                            Compare(
                                left=Name(id=izumkonata, ctx=Load(), lineno=5, col_offset=0),
                                ops=[NotEq()],
                                comparators=[Constant(value=False, lineno=5, col_offset=0)]
                            )
                        ]
                    ),
                    body=[
                        Try(
                            body=[
                                Expr(
                                    value=Tuple(
                                        elts=[
                                            BinOp(Constant(1), Div(), Constant(0)),
                                            BinOp(Constant(123), Div(), Constant(0)),
                                            BinOp(Constant(12312321312), Div(), Constant(0))
                                        ],
                                        ctx=Load()
                                    ),
                                    lineno=6,
                                    col_offset=8
                                )
                            ],
                            handlers=[
                                ExceptHandler(
                                    type=None,
                                    name=None,
                                    body=[Pass(lineno=7, col_offset=8)]
                                )
                            ],
                            orelse=[],
                            finalbody=[],
                            lineno=6,
                            col_offset=4
                        )
                    ],
                    orelse=[
                        If(
                            test=BoolOp(
                                op=Or(),
                                values=[
                                    Compare(
                                        left=Name(id=anhnguyencoder, ctx=Load(), lineno=8, col_offset=0),
                                        ops=[Eq()],
                                        comparators=[Constant(value="izu", lineno=8, col_offset=0)]
                                    ),
                                    Compare(
                                        left=Name(id=izumkonata, ctx=Load(), lineno=8, col_offset=0),
                                        ops=[Eq()],
                                        comparators=[Constant(value=False, lineno=8, col_offset=0)]
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
                                                vararg=None,
                                                kwonlyargs=[],
                                                kw_defaults=[],
                                                kwarg=None,
                                                defaults=[]
                                            ),
                                            body=Call(
                                                func=Name(id="print", ctx=Load(), lineno=9, col_offset=0),
                                                args=[Constant(value="bietdepzairoi", lineno=9, col_offset=0)],
                                                keywords=[]
                                            )
                                        ),
                                        args=[],
                                        keywords=[]
                                    ),
                                    lineno=9,
                                    col_offset=4
                                )
                            ],
                            orelse=[
                                While(
                                    test=Constant(value=True, lineno=10, col_offset=0),
                                    body=[Pass(lineno=10, col_offset=8)],
                                    orelse=[],
                                    lineno=10,
                                    col_offset=4
                                ),
                                Expr(
                                    value=Call(
                                        func=Name(id="print", ctx=Load(), lineno=11, col_offset=0),
                                        args=[Constant(value="deccailolnhamay", lineno=11, col_offset=0)],
                                        keywords=[]
                                    ),
                                    lineno=11,
                                    col_offset=4
                                )
                            ],
                            lineno=8,
                            col_offset=0
                        )
                    ],
                    lineno=5,
                    col_offset=0
                )
            ],
            lineno=3,
            col_offset=0
        )
    ]

class junk(ast.NodeTransformer):

    def visit_Module(self, node):
        for i, j in enumerate(node.body):

            if isinstance(j, (ast.FunctionDef, ast.ClassDef)):
                self.visit(j)

            junk_blocks = [gen_jcode(j) for _ in range(2)]

            node.body[i] = junk_blocks + [j]

        return node

    def visit_FunctionDef(self, node):
        for i, j in enumerate(node.body):
            junk_blocks = [gen_jcode(j) for _ in range(2)]
            node.body[i] = junk_blocks + [j]
        return node

    def visit_ClassDef(self, node):
        for i, j in enumerate(node.body):
            junk_blocks = [gen_jcode(j) for _ in range(2)]
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
