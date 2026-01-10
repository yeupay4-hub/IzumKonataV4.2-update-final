## Hi everybody!
-> This project will no longer be sold, so I will share it for free with you.

-> Using this obf for bad purposes, the owner will not be responsible!

## 🌀 IzumKonata Obfuscator.

-> High-Speed Obfuscated Engine – Advanced Anti-Tamper - Anti-Crack – Anti-Debug – Anti-VM – Multi-Layer Compression

![Ảnh chụp màn hình 2025-12-28 160813](https://github.com/user-attachments/assets/cdf881fc-692f-464b-956a-93fcc21d0b00)

-> A powerful, high‑speed Python obfuscator with multi‑layer protection, featuring anti-debug, anti-crack like http toolkit software,... anti-tamper, anti-hook requests, and a fully customized encryption system.

## 🌟 Outstanding features.

# 🔐 1. Obfuscation According to AST

-> IzumKonata operates directly on AST (Abstract Syntax Tree), helping:

-> Code structure is completely changed

-> Almost impossible to reverse to original form

-> All strings, ints are encoded through multi-layer lambda

## 🛡 2. Extremely Strong Anti-Debug / Anti-Tamper / Anti-Hook

→ Integrates nearly 70+ security checks, including:

-> Do not allow file editing

-> Prevent decryption when dis.dis Marshal.loads

-> Check fixed line number

-> Check builtins, builtins.exec, builtins.eval are hooked

-> Check module requests are replaced

-> Prohibit sitecustomize / usercustomize

-> Check all method ID & source of class

-> Check user key & CRC to prevent cracking

## ⚙️ 3. Multi-Layer Compression

→ After compiling to bytecode, the code passes through a 4-layer compression chain:

- LZMA

- ZLIB

- BZ2

- Base85 (A85)

→ Result: extremely hard to analyze and nearly unreadable.

## 🧩 4. Built-in Protection (Hide Builtins).

All built-in functions such as eval, exec, print, len, ...
are protected with anti-hook + anti-debug mechanisms.

## 🗑 5. Junk Code Injection.

Random junk code is inserted into every block.

## ✨ 6. F-String to Join Conversion.

-> Prevents grepping or detection of real content.

## 🎨 7. Beautiful Banner + CLI.

-> Uses pystyle to create an attractive command-line interface.

## 📊 Obfuscation Process.

```mermaid
graph TD
    A[Original Python Code] --> AA[Inject Anti-Tamper]
    AA --> AB[Inject Anti-Debug and Anti-Proxy]
    AB --> AC[Double Integrity Check]

    AC --> B[AST Parse]
    B --> C[F-String Transformation]
    C --> D[Hide Builtins]

    D --> E[Obfuscate Literals]
    E --> F[Inject Junk Code]

    F --> G[Unparse AST to Python Source]
    G --> H[Compile to Code Object]
    H --> I[Marshal Serialization]

    I --> J[LZMA Compression]
    J --> K[Zlib Compression]
    K --> L[BZ2 Compression]
    L --> M[Base85 Encoding]

    M --> N[Insert Into Lobby Template]
    N --> O[Write USER and CRC]
    O --> P[Generate Final Obfuscated File]
```

## 🚀 Installation.

Python 3.8+ or later

Module: pystyle (auto install if missing)

## 📖 Usage.

-> Run the obfuscator depending on your device:

-> Android (Termux): python Izu311.py or python Izu312.py

-> Windows CMD / PC: python Izu311.py or python Izu312.py

- Enter the file to encode:
- Enter File: your_script.py

- Enter the username to embed:
- Enter Your Username! [For example: 'AnhNguyenCoder']:

# Choose options:
-> Do you want high security? Yes (Y) | (N) No:

-> Anti-Crack? (Y) Yes | (N) No:

-> Anti-Debug? (Y) Yes | (N) No:

# After encoding:
-> Saved file name: obf-your_script.py
-> Execution time: 0.00s

## ⚠️ Important Notice!

-> This tool is intended solely for legal code protection purposes. The author is not responsible for any misuse!

## 🤝 Contributing.

->> We welcome all contributions! Please submit a Pull Request. For major changes, open an Issue to discuss what you want to modify.

## 📞 Contact
-> Author: Nguyen Nhat Nam Anh

-> Telegram: https://t.me/ctevclwar

-> Facebook: https://www.facebook.com/ng.xau.k25
