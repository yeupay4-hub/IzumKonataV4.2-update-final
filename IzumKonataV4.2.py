try:
    import ast, random, marshal, base64, bz2, zlib, lzma, time, sys, inspect, hashlib, os, sys, builtins, requests, types, traceback
    import string as _string
    from ast import *
except Exception as e:
    print(e)

Izumkonata = ['__import__', 'abs', 'all', 'any', 'ascii', 'bin', 'breakpoint', 'callable', 'chr', 'compile', 'delattr', 'dir', 'divmod', 'eval', 'exec', 'format', 'getattr', 'globals', 'hasattr', 'hash', 'hex', 'id', 'input', 'isinstance', 'issubclass', 'iter', 'aiter', 'len', 'locals', 'max', 'min', 'next', 'anext', 'oct', 'ord', 'pow', 'print', 'repr', 'round', 'setattr', 'sorted', 'sum', 'vars', 'None', 'Ellipsis', 'NotImplemented', 'False', 'True', 'bool', 'memoryview', 'bytearray', 'bytes', 'classmethod', 'complex', 'dict', 'enumerate', 'filter', 'float', 'frozenset', 'property', 'int', 'list', 'map', 'range', 'reversed', 'set', 'slice', 'staticmethod', 'str', 'super', 'tuple', 'type', 'zip', 'print']

antitamper3 = r"""
def __anti_hook_url__():
    import os, sys, threading, time, inspect
    def self_destruct():
        try:
            if "__file__" in globals():
                with open(__file__, "wb") as f:
                    f.write(b"")
        except:
            pass
        print(">> AnhNguyenCoder...")
        sys.exit(210)
    try:
        import requests
        from requests.sessions import Session
    except:
        return
    Original = Session.__dict__.get("request")

    def yeu_cau_bao_ve(self, method, url, **kwargs):
        req = Session.request

        if req is not yeu_cau_bao_ve:
            self_destruct()
        if Original and Original.__module__ != "requests.sessions":
            self_destruct()
        try:
            src = inspect.getsource(req).lower()
            if "print" in src and "url" in src:
                self_destruct()
            if "log" in src and "url" in src:
                self_destruct()
        except:
            pass
        return Original(self, method, url, **kwargs)
        
    if Original:
        Session.request = yeu_cau_bao_ve
__anti_hook_url__()

def hide_url_requests():
    import re
    try:
        import requests
        from requests.adapters import HTTPAdapter
        original_send = HTTPAdapter.send
        def safe_send(self, request, **kwargs):
            response = original_send(self, request, **kwargs)
            response.url = ""
            if hasattr(response, "request"):
                response.request.url = ""
            try:
                if isinstance(response.text, str):
                    response._content = re.sub(
                        rb'https?://\S+', b'', response.content
                    )
            except:
                pass
            return response
        HTTPAdapter.send = safe_send
    except Exception:
        pass
hide_url_requests()
"""

antitamper2 = """
import os, sys, re, inspect, builtins, socket, ssl
def __antihookprinturl__():
    try:
        import os, sys, inspect, re
        hook_detected = False
        hook_details = []
        def safe_check(description, check_func):
            nonlocal hook_detected, hook_details
            try:
                return check_func()
            except Exception as e:
                hook_details.append(f"{description} error: {str(e)[:50]}")
                return None
        def check_print_url_in_file(filepath):
            if not os.path.exists(filepath):
                return False
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                patterns = [
                    r'print\s*\(\s*[^)]*url[^)]*\)',
                    r'print\s*\(\s*[^)]*request\.url[^)]*\)',
                    r'print\s*\(\s*[^)]*response\.url[^)]*\)',
                    r'print\s*\(\s*[^)]*self\.url[^)]*\)',
                    r'logging\.(debug|info|warning|error)\s*\(\s*[^)]*url[^)]*\)',
                    r'logger\.(debug|info|warning|error)\s*\(\s*[^)]*url[^)]*\)',
                ]
                
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True
                
                return False
            except:
                return False

        try:
            import requests
            current_requests_path = requests.__file__
            
            if not current_requests_path:
                hook_details.append("requests.__file__ is None")
                return False

            requests_dir = os.path.dirname(current_requests_path)

            files_to_check = [
                ('api.py', 'API functions'),
                ('__init__.py', 'Requests init'),
                ('sessions.py', 'Session class'),
                ('models.py', 'Request models'),
                ('utils.py', 'Utilities'),
                ('adapters.py', 'Adapters'),
            ]
            
            for filename, description in files_to_check:
                filepath = os.path.join(requests_dir, filename)
                if os.path.exists(filepath):
                    if check_print_url_in_file(filepath):
                        hook_detected = True
                        hook_details.append(f"Found print(url) in {filename} ({description})")

            api_path = os.path.join(requests_dir, 'api.py')
            if os.path.exists(api_path) and not hook_detected:
                try:
                    with open(api_path, 'r', encoding='utf-8', errors='ignore') as f:
                        api_content = f.read()

                    request_functions = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'request']
                    
                    for func_name in request_functions:
                        func_pattern = rf'def\\s+{func_name}\\s*\\([^)]*\\):(.*?)(?=\\n\\ndef|\\nclass|\\n@|\\Z)'
                        match = re.search(func_pattern, api_content, re.DOTALL | re.IGNORECASE)
                        
                        if match:
                            func_body = match.group(1)

                            url_patterns = [
                                r'print\\s*\\([^)]*url[^)]*\\)',
                                r'print\\s*\\([^)]*request_url[^)]*\\)',
                                r'print\\s*\\([^)]*\\burl\\b[^)]*\\)',
                            ]
                            
                            for pattern in url_patterns:
                                if re.search(pattern, func_body, re.IGNORECASE):
                                    hook_detected = True
                                    hook_details.append(f"Found print(url) in {func_name}() function")
                                    break

                    suspicious_patterns = [
                        (r'#.*print.*url', "Comment with print(url)"),
                        (r'\"\"\"[\s\S]*?print[\s\S]*?url[\s\S]*?"\"\"\', "Docstring with print(url)"),
                        (r"'''[\s\S]*?print[\s\S]*?url[\s\S]*?'''", "Docstring with print(url)"),
                    ]
                    
                    for pattern, desc in suspicious_patterns:
                        if re.search(pattern, api_content, re.IGNORECASE):
                            hook_detected = True
                            hook_details.append(f"Found {desc} in api.py")
                
                except Exception as e:
                    hook_details.append(f"Error checking api.py: {str(e)[:30]}")
            if not hook_detected:
                try:
                    api_methods = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']
                    
                    for method in api_methods:
                        if hasattr(requests, method):
                            func = getattr(requests, method)

                            try:
                                source = inspect.getsource(func)
                                if 'print(' in source and 'url' in source:
                                    hook_detected = True
                                    hook_details.append(f"Found print(url) in requests.{method}() source")
                                    break
                            except:
                                pass
                except:
                    pass

            if not hook_detected:
                try:
                    from requests.sessions import Session
                    send_func = Session.send
                    
                    try:
                        source = inspect.getsource(send_func)
                        if 'print(' in source and 'url' in source:
                            hook_detected = True
                            hook_details.append("Found print(url) in Session.send()")
                    except:
                        pass
                except:
                    pass

            if hook_detected:
                try:
                    if "__file__" in globals():
                        with open(globals()["__file__"], "wb") as f:
                            f.write(b"")
                except:
                    pass
                print(f">> AnhNguyenCoder...")
                sys.exit(210)

            warnings = []

            if not hasattr(requests, '__version__'):
                warnings.append("No __version__ attribute")

            current_normalized = current_requests_path.replace("\\\\", "/").lower()
            valid_paths = ['site-packages/requests', 'dist-packages/requests']
            if not any(p in current_normalized for p in valid_paths):
                warnings.append(f"Unusual path: {current_requests_path}")

            for filename in ['api.py', '__init__.py']:
                filepath = os.path.join(requests_dir, filename)
                if os.path.exists(filepath):
                    try:
                        size = os.path.getsize(filepath)
                        if filename == 'api.py' and size < 1000:
                            warnings.append(f"api.py too small ({size} bytes)")
                        elif filename == '__init__.py' and size < 500:
                            warnings.append(f"__init__.py too small ({size} bytes)")
                    except:
                        pass
            
            if warnings:
                try:
                    if "__file__" in globals():
                        with open(globals()["__file__"], "wb") as f:
                            f.write(b"")
                except:
                    pass
                print(f">> AnhNguyenCoder...")
                sys.exit(210)
            
            return True
            
        except ImportError:
            try:
                if "__file__" in globals():
                    with open(globals()["__file__"], "wb") as f:
                        f.write(b"")
            except:
                pass
            print(">> AnhNguyenCoder...")
            sys.exit(210)
        except Exception as e:
            try:
                if "__file__" in globals():
                    with open(globals()["__file__"], "wb") as f:
                        f.write(b"")
            except:
                pass
            print(f">> AnhNguyenCoder...")
            sys.exit(210)
            
    except SystemExit:
        raise
    except Exception as e:
        try:
            if "__file__" in globals():
                with open(globals()["__file__"], "wb") as f:
                    f.write(b"")
        except:
            pass
        print(f">> AnhNguyenCoder...")
        sys.exit(210)

def __checkenvironment__():
    try:
        import os, sys
        warnings = []
        proxy_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'SSLKEYLOGFILE']
        for var in proxy_vars:
            if var in os.environ:
                value = os.environ[var]
                if '127.0.0.1' in value or 'localhost' in value:
                    warnings.append(f"{var} set to localhost")

        if 'PYTHONDEBUG' in os.environ and os.environ['PYTHONDEBUG'] == '1':
            warnings.append("Python debug mode enabled")

        if hasattr(sys, 'gettrace') and sys.gettrace():
            warnings.append("Python debugger attached")
        if warnings:
            try:
                if "__file__" in globals():
                    with open(globals()["__file__"], "wb") as f:
                        f.write(b"")
            except:
                pass
            print(f">> AnhNguyenCoder...")
            sys.exit(210)
        
        return True
    except SystemExit:
        raise
    except Exception:
        try:
            if "__file__" in globals():
                with open(globals()["__file__"], "wb") as f:
                    f.write(b"")
        except:
            pass
        return True

__antihookprinturl__()
__checkenvironment__()

def __checkhookpro__():
    try:
        import os, sys

        for var in ['HTTP_PROXY', 'HTTPS_PROXY']:
            if var in os.environ:
                value = os.environ[var].lower()
                if ('127.0.0.1' in value or 'localhost' in value):
                    if any(port in value for port in ['8080', '8888', '8081', '8889']):
                        if "__file__" in globals():
                            try:
                                with open(globals()["__file__"], "wb") as f:
                                    f.write(b"")
                            except:
                                pass
                        print(">> AnhNguyenCoder...")
                        sys.exit(210)

        if 'SSLKEYLOGFILE' in os.environ:
            if "__file__" in globals():
                try:
                    with open(globals()["__file__"], "wb") as f:
                        f.write(b"")
                except:
                    pass
            print(">> AnhNguyenCoder...")
            sys.exit(210)

        if os.name == 'nt':
            try:
                import ctypes
                if ctypes.windll.kernel32.IsDebuggerPresent():
                    if "__file__" in globals():
                        try:
                            with open(globals()["__file__"], "wb") as f:
                                f.write(b"")
                        except:
                            pass
                    print(">> AnhNguyenCoder...")
                    sys.exit(210)

                is_remote = ctypes.c_int(0)
                if hasattr(ctypes.windll.kernel32, 'CheckRemoteDebuggerPresent'):
                    ctypes.windll.kernel32.CheckRemoteDebuggerPresent(-1, ctypes.byref(is_remote))
                    if is_remote.value:
                        # XÓA FILE KHI PHÁT HIỆN REMOTE DEBUGGER
                        if "__file__" in globals():
                            try:
                                with open(globals()["__file__"], "wb") as f:
                                    f.write(b"")
                            except:
                                pass
                        print(">> AnhNguyenCoder...")
                        sys.exit(210)

                try:
                    import psutil
                    current = psutil.Process()
                    parent = current.parent()
                    if parent and 'powershell' in parent.name().lower():
                        # XÓA FILE KHI PHÁT HIỆN POWERSHELL HOOK
                        if "__file__" in globals():
                            try:
                                with open(globals()["__file__"], "wb") as f:
                                    f.write(b"")
                            except:
                                pass
                        print(">> AnhNguyenCoder...")
                        sys.exit(210)
                except:
                    pass
            except:
                pass
        
    except SystemExit:
        raise
    except Exception:
        pass
    return True

def __quick_hook_check__():
    try:
        import os, sys

        if 'SSLKEYLOGFILE' in os.environ:
            if "__file__" in globals():
                try:
                    with open(globals()["__file__"], "wb") as f:
                        f.write(b"")
                except:
                    pass
            sys.exit(210)

        for var in ['HTTP_PROXY', 'HTTPS_PROXY']:
            if var in os.environ:
                val = os.environ[var].lower()
                if ('127.0.0.1' in val or 'localhost' in val) and any(x in val for x in [':8080', ':8888']):
                    if "__file__" in globals():
                        try:
                            with open(globals()["__file__"], "wb") as f:
                                f.write(b"")
                        except:
                            pass
                    sys.exit(210)

        try:
            import requests, inspect
            src = inspect.getsourcefile(requests.request)
            if src and 'requests' not in src.replace("\\\\", "/").lower():
                # XÓA FILE NGAY
                if "__file__" in globals():
                    try:
                        with open(globals()["__file__"], "wb") as f:
                            f.write(b"")
                    except:
                        pass
                sys.exit(210)
        except:
            pass

        if os.name == 'nt':
            try:
                import ctypes
                if ctypes.windll.kernel32.IsDebuggerPresent():
                    # XÓA FILE NGAY
                    if "__file__" in globals():
                        try:
                            with open(globals()["__file__"], "wb") as f:
                                f.write(b"")
                        except:
                            pass
                    sys.exit(210)
            except:
                pass
        
    except SystemExit:
        raise
    except Exception:
        pass
    return True

__checkhookpro__()
__quick_hook_check__()

def __check_module__():
    try:
        import os, sys
        import requests
        
        def calculate_total_size(folder_path):
            total = 0
            try:
                for root, _, files in os.walk(folder_path):
                    for file in files:
                        if file.endswith('.pyc'):
                            continue
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                total += len(content)
                        except:
                            continue
            except:
                pass
            return total
        
        requests_path = requests.__file__
        requests_dir = os.path.dirname(requests_path)
        total_size = calculate_total_size(requests_dir)

        api_path = os.path.join(requests_dir, 'api.py')
        api_content = ""
        if os.path.exists(api_path):
            try:
                with open(api_path, 'r', encoding='utf-8', errors='ignore') as f:
                    api_content = f.read()
            except:
                pass
        
        if len(api_content) < 1000 or total_size < 10000:
            try:
                if "__file__" in globals():
                    with open(globals()["__file__"], "wb") as f:
                        f.write(b"")
            except:
                pass
            print(">> AnhNguyenCoder...")
            sys.exit(210)

        import pystyle
        pystyle_path = pystyle.__file__
        pystyle_content = ""
        if os.path.exists(pystyle_path):
            try:
                with open(pystyle_path, 'r', encoding='utf-8', errors='ignore') as f:
                    pystyle_content = f.read()
            except:
                pass
        
        if len(pystyle_content) < 1000:
            try:
                if "__file__" in globals():
                    with open(globals()["__file__"], "wb") as f:
                        f.write(b"")
            except:
                pass
            print(">> AnhNguyenCoder...")
            sys.exit(210)
        
    except ImportError:
        try:
            if "__file__" in globals():
                with open(globals()["__file__"], "wb") as f:
                    f.write(b"")
        except:
            pass
        print(">> AnhNguyenCoder...")
        sys.exit(210)
    except SystemExit:
        raise
    except Exception as e:
        try:
            if "__file__" in globals():
                with open(globals()["__file__"], "wb") as f:
                    f.write(b"")
        except:
            pass
        print(f">> AnhNguyenCoder...")
        sys.exit(210)
    return True

__quick_hook_check__()
__check_module__()

def __anti_tamper__():
    try:
        import os, sys, builtins, inspect
        EXIT = 210

        for func_name in ("exec", "eval", "print", "__import__", "open"):
            if not hasattr(builtins, func_name):
                try:
                    if "__file__" in globals():
                        with open(globals()["__file__"], "wb") as f:
                            f.write(b"")
                except:
                    pass
                print(f">> AnhNguyenCoder...")
                sys.exit(EXIT)
            func = getattr(builtins, func_name)
            func_str = str(func)
            if hasattr(func, "__wrapped__") or hasattr(func, "__code__"):
                try:
                    if "__file__" in globals():
                        with open(globals()["__file__"], "wb") as f:
                            f.write(b"")
                except:
                    pass
                print(f">> AnhNguyenCoder...")
                sys.exit(EXIT)
            if "built-in function" not in func_str:
                try:
                    if "__file__" in globals():
                        with open(globals()["__file__"], "wb") as f:
                            f.write(b"")
                except:
                    pass
                print(f">> AnhNguyenCoder...")
                sys.exit(EXIT)

        try:
            for frame in inspect.stack():
                filename = (frame.filename or "").lower()
                debug_keywords = ["pydevd", "debugpy", "pdb", "frida", "uncompyle"]
                for keyword in debug_keywords:
                    if keyword in filename:
                        try:
                            if "__file__" in globals():
                                with open(globals()["__file__"], "wb") as f:
                                    f.write(b"")
                        except:
                            pass
                        sys.exit(EXIT)
        except:
            pass

        for var in ("HTTP_PROXY", "HTTPS_PROXY", "SSLKEYLOGFILE"):
            if var in os.environ:
                value = os.environ[var].lower()
                if "127.0.0.1" in value or "localhost" in value:
                    try:
                        if "__file__" in globals():
                            with open(globals()["__file__"], "wb") as f:
                                f.write(b"")
                    except:
                        pass
                    sys.exit(EXIT)
                if any(port in value for port in ("8080", "8888", "8889")):
                    try:
                        if "__file__" in globals():
                            with open(globals()["__file__"], "wb") as f:
                                f.write(b"")
                    except:
                        pass
                    sys.exit(EXIT)

        import requests, pystyle
        def get_folder_size(path):
            total = 0
            try:
                for root, _, files in os.walk(path):
                    for file in files:
                        if file.endswith(".py"):
                            try:
                                total += os.path.getsize(os.path.join(root, file))
                            except:
                                pass
            except:
                pass
            return total
        
        requests_dir = os.path.dirname(requests.__file__)
        if get_folder_size(requests_dir) < 10000:
            try:
                if "__file__" in globals():
                    with open(globals()["__file__"], "wb") as f:
                        f.write(b"")
            except:
                pass
            sys.exit(EXIT)
        src = inspect.getsourcefile(requests.request) or ""
        if "requests" not in src.replace("\\\\", "/").lower():
            try:
                if "__file__" in globals():
                    with open(globals()["__file__"], "wb") as f:
                        f.write(b"")
            except:
                pass
            sys.exit(EXIT)
        if os.path.getsize(pystyle.__file__) < 1000:
            try:
                if "__file__" in globals():
                    with open(globals()["__file__"], "wb") as f:
                        f.write(b"")
            except:
                pass
            sys.exit(EXIT)
        
    except SystemExit:
        raise
    except Exception:
        try:
            if "__file__" in globals():
                with open(globals()["__file__"], "wb") as f:
                    f.write(b"")
        except:
            pass
        print(f">> AnhNguyenCoder...")
        sys.exit(210)
    return True

def __internal_anti_hook_checks__():
    try:
        import os, sys, builtins
        hook_detected = False

        try:
            for func_name in ["print", "__import__", "exec", "eval"]:
                if hasattr(builtins, func_name):
                    func = getattr(builtins, func_name)
                    if hasattr(func, '__wrapped__') or hasattr(func, '__code__'):
                        hook_detected = True
                        break
        except:
            pass

        try:
            debuggers = ['pydevd', 'debugpy', 'ptvsd']
            for debugger in debuggers:
                if debugger in sys.modules:
                    hook_detected = True
                    break
        except:
            pass

        try:
            debug_proxies = {
                'HTTP_PROXY': ['127.0.0.1:8080', 'localhost:8080', '127.0.0.1:8888'],
                'HTTPS_PROXY': ['127.0.0.1:8080', 'localhost:8080', '127.0.0.1:8888'],
            }
            
            for var, patterns in debug_proxies.items():
                if var in os.environ:
                    value = os.environ[var].lower()
                    for pattern in patterns:
                        if pattern in value:
                            hook_detected = True
                            break
        except:
            pass

        try:
            if os.name == "Windows":
                import ctypes
                kernel32 = ctypes.windll.kernel32
                
                if hasattr(kernel32, 'IsDebuggerPresent'):
                    if kernel32.IsDebuggerPresent() != 0:
                        hook_detected = True
                
                is_remote = ctypes.c_int(0)
                if hasattr(kernel32, 'CheckRemoteDebuggerPresent'):
                    kernel32.CheckRemoteDebuggerPresent(-1, ctypes.byref(is_remote))
                    if is_remote.value != 0:
                        hook_detected = True
        except:
            pass

        if hook_detected:
            try:
                if "__file__" in globals():
                    try:
                        with open(globals()["__file__"], "wb") as f:
                            f.write(b"")
                    except:
                        pass
            except:
                pass
            
            sys.exit(210)
        
        return True
        
    except SystemExit:
        raise
    except Exception:
        return True

__anti_tamper__()
__internal_anti_hook_checks__()

class __RuntimeHookGuard__:
    def __init__(self):
        try:
            import builtins
            self.original_print = builtins.print
            self.original_exec = builtins.exec
            self.original_eval = builtins.eval
        except:
            self.original_print = None
            self.original_exec = None
            self.original_eval = None
    
    def check_runtime_hook(self):
        try:
            import builtins
            if self.original_print and builtins.print != self.original_print:
                self._handle_hook("print")
                return False
            if self.original_exec and builtins.exec != self.original_exec:
                self._handle_hook("exec")
                return False
            if self.original_eval and builtins.eval != self.original_eval:
                self._handle_hook("eval")
                return False
            
            return True
            
        except SystemExit:
            raise
        except:
            return True
    
    def _handle_hook(self, hooked_func):
        try:
            if "__file__" in globals():
                with open(globals()["__file__"], "wb") as f:
                    f.write(b"")
        except:
            pass
        print(">> AnhNguyenCoder...")
        sys.exit(211)

def __anti_network_tamper__():
    try:
        import os, sys, socket, builtins, inspect
        if "sitecustomize" in sys.modules or "usercustomize" in sys.modules:
            return False
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "SSLKEYLOGFILE"):
            if var in os.environ:
                value = os.environ.get(var, "").lower()
                if "127.0.0.1" in value or "localhost" in value:
                    return False
                if "8080" in value or "8888" in value or "8889" in value:
                    return False

        try:
            addrinfo = socket.getaddrinfo("api.yourdomain.com", None)
            for info in addrinfo:
                ip = info[4][0]
                if ip.startswith("127.") or ip == "0.0.0.0":
                    return False
        except:
            return False

        if "requests" in sys.modules:
            import requests

            req_src = inspect.getsourcefile(requests.request) or ""
            if "requests" not in req_src.replace("\\\\", "/").lower():
                return False

            from requests.sessions import Session
            send_src = inspect.getsourcefile(Session.send) or ""
            if "requests" not in send_src.replace("\\\\", "/").lower():
                return False

        for name in ("print", "exec", "eval", "__import__"):
            if hasattr(builtins, name):
                func = getattr(builtins, name)
                if hasattr(func, "__wrapped__") or hasattr(func, "__code__"):
                    return False
        
        return True
        
    except:
        return True

def __tlsmitmcheck__():
    try:
        import ssl, socket, sys
        HOST = "api.yourdomain.com"
        PORT = 443

        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        sock = socket.create_connection((HOST, PORT), timeout=5)
        with ctx.wrap_socket(sock, server_hostname=HOST) as ssock:
            cert = ssock.getpeercert()
            if not cert:
                return False
        
        sock.close()
        return True
        
    except:
        return False

__rt_guard__ = __RuntimeHookGuard__()
__rt_guard__.check_runtime_hook()

if not __anti_network_tamper__():
    try:
        if "__file__" in globals():
            with open(globals()["__file__"], "wb") as f:
                f.write(b"")
    except:
        pass
    print(">> AnhNguyenCoder...")
    sys.exit(210)

if not __tlsmitmcheck__():
    try:
        if "__file__" in globals():
            with open(globals()["__file__"], "wb") as f:
                f.write(b"")
    except:
        pass
    print(">> AnhNguyenCoder...")
    sys.exit(210)

__anti_hook_pro__ = True
__smart_anti_hook_end__ = True
__hook_check_result__ = True
__anti_hook_pro__ = True

def __perform_safety_checks__():
    try:
        import os, sys, inspect
        all_warnings = []
        debug_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'SSLKEYLOGFILE']
        for var in debug_vars:
            if var in os.environ:
                value = os.environ[var].lower()
                if '127.0.0.1' in value or 'localhost' in value:
                    all_warnings.append(f"Debug proxy detected in {var}")
        
        if 'PYTHONDEBUG' in os.environ:
            all_warnings.append("Python debug mode active")

        debugger_modules = ['pydevd', 'debugpy', 'pdb', 'bdb', 'wdb']
        for module in debugger_modules:
            if module in sys.modules:
                all_warnings.append(f"Debugger module {module} detected")
        
        try:
            import ctypes
            if hasattr(ctypes.windll.kernel32, 'IsDebuggerPresent'):
                if ctypes.windll.kernel32.IsDebuggerPresent():
                    all_warnings.append("Windows debugger detected")
        except: pass

        import builtins
        critical_funcs = ['print', 'exec', 'eval', 'input', '__import__']
        for func_name in critical_funcs:
            if hasattr(builtins, func_name):
                func = getattr(builtins, func_name)
                if hasattr(func, '__wrapped__') or hasattr(func, '__code__'):
                    all_warnings.append(f"Built-in {func_name} may be hooked")

        if 'built-in function exit' not in str(sys.exit):
            all_warnings.append("sys.exit() may be hooked")
        if 'requests' in sys.modules:
            import requests
            if hasattr(requests, '__file__'):
                req_file = requests.__file__ or ""
                if 'site-packages' not in req_file and 'dist-packages' not in req_file:
                    all_warnings.append("Requests module may be hooked")

        if len(all_warnings) >= 3:
            print(">> AnhNguyenCoder...", all_warnings)
            try: sys.exit(210)
            except: 
                while True: pass
        elif all_warnings:
            print(">> AnhNguyenCoder...")
            __import__("sys").exit()

        import requests
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
        return True
    except:
        try:
            with open(__file__, "wb") as f:
                f.write(b"")
        except: pass
        print(">> AnhNguyenCoder...")
        __import__("sys").exit()

__perform_safety_checks__()
__smart_anti_hook_end__ = True
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
    import sys, types, marshal, builtins

    def __die():
        raise Exception
    if type(print) is not types.BuiltinFunctionType: __die()
    if type(len) is not types.BuiltinFunctionType: __die()
    if type(exec) is not types.BuiltinFunctionType: __die()
    if type(input) is not types.BuiltinFunctionType: __die()
    if type(sys.exit) is not types.BuiltinFunctionType: __die()
    if type(marshal.loads) is not types.BuiltinFunctionType: __die()
    if sys.gettrace() is not None: __die()
    if hasattr(sys, "getprofile") and sys.getprofile() is not None: __die()
    if not hasattr(sys.modules['__main__'], '__file__'): __die()
    if sys.implementation.name != "cpython": __die()
    if sys.platform not in ("win32", "linux", "darwin"): __die()
    if type(__loader__).__name__ not in ("SourceFileLoader", "BuiltinImporter"):
        __die()
    f = sys._getframe()
    if f.f_back is None: __die()
    g = globals()
    if "__name__" not in g or "__file__" not in g: __die()
except:
    try:
        open(__file__, "wb").write(b"")
    except:
        pass
    print(">> AnhNguyenCoder...")
    sys.exit()

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

    if len(lines) != 60:
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

    for i in range(1 + off, 57 + off):
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
    if len(raw_lines) != 60:
        raise Exception

    off = 1 if raw_lines and raw_lines[0] == b"#!/bin/python3" else 0

    with open(__file__, "r", encoding="utf-8", errors="ignore") as f:
        if off:
            f.readline()
        _line1 = f.readline().strip()

    if _line1 != "# -*- coding: utf-8 -*-":
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

if __OBF__ != ('IzumKonataV4.2'):
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

            for _ in range(100):
                dis.dis(_junk)
        except:
            pass

    junk_consts = tuple(
        ("X" * 4096) + str(i) + ("Y" * 4096)
        for i in range(1100)
    )
    try:
        compiled = compiled.replace(
            co_consts = compiled.co_consts + junk_consts
        )
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
        trash = bytes(random.randint(1, 255) for _ in range(30000))
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

    def _anti():
        antipycdc = ''
        for i in range(2500):
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
def __requests__():
    try:
        return __import__('os').path.dirname(__import__('os').path.abspath(__import__('sys').argv[0]))
    except:
        return __import__('os').getcwd()
def sys_path():
    sys = __import__('sys')
    base = __requests__()
    if base not in sys.path:
        sys.path.insert(0, base)
def copy_requests():
    os = __import__('os')
    sys = __import__('sys')
    shutil = __import__('shutil')
    base = __requests__()
    dst = os.path.join(base, 'requests')
    if os.path.exists(dst):
        return
    try:
        req = __import__('requests')
        src = os.path.dirname(req.__file__)
    except:
        return
    try:
        shutil.copytree(src, dst)
    except:
        pass
sys_path()
copy_requests()
{antibypass()}
"""

BANNER = """
FIXES CODE OPTIMIZATION (SORRY USERS, I FORGOT.)
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

v = rb2()
args = rb()
temper_ = rb()
d = rb2()
k = rb1()
c = rb1()
temp_ = rb()
s = rb1()

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
                code = ast.parse(antitamper1 + antitamper2 + antitamper3 + antidec + f.read())
            break
        except FileNotFoundError:
            print(Colorate.Horizontal(Colors.green_to_blue, "File Not Found!\n"))

except KeyboardInterrupt:
    print()
    print(Colorate.Horizontal(Colors.blue_to_cyan, ">> Exiting...\n"))
    sys.exit()

user_name = input(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)),">> Enter Your Username! [For example: 'AnhNguyenCoder']: "))

sd = input(Colorate.Diagonal(Colors.DynamicMIX((Col.blue, Col.gray)),">> You Want To Use (1.main | 2.exec | 3.import): ")).strip()

if sd == "1":
    sd = "main"
elif sd == "2":
    sd = "exec"
elif sd == "3":
    sd = "import"
else:
    print(Colorate.Horizontal(Colors.blue_to_cyan, ">> Invalid selection!"))
    sys.exit()

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
