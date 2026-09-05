# 📱 MOBILE REV & EXPLOIT ENGINEERING CTF

## Practical Write-Up & Analysis Template

> Template ini digunakan untuk mengerjakan dan mendokumentasikan challenge Android CTF.
>
> Environment:
>
> ```text
> Kali Linux WSL2
> Android Emulator
> JADX
> ADB
> Frida
> Ghidra
> Python
> ```

---

# 0. Challenge Information

```text
CTF:
Category:
Challenge:
Points:
Author:
Difficulty:
APK:
Flag format:
```

Challenge description:

```text
[PASTE DESCRIPTION HERE]
```

Initial hypothesis:

```text
[WHAT DO I THINK THE CHALLENGE IS ABOUT?]
```

---

# 1. Environment Check

Sebelum mulai challenge, pastikan semua tool bekerja.

## 1.1 JADX

```bash
jadx --version
```

Expected:

```text
1.5.x
```

GUI:

```bash
jadx-gui
```

---

## 1.2 ADB

```bash
adb --version
```

Check device:

```bash
adb devices
```

Expected:

```text
List of devices attached
emulator-5554    device
```

Kalau kosong:

```bash
adb kill-server
adb start-server
adb devices
```

---

## 1.3 Android Architecture

```bash
adb shell getprop ro.product.cpu.abi
```

Record:

```text
Architecture:
```

---

## 1.4 Frida

```bash
frida --version
```

Record:

```text
Frida Client:
Frida Server:
```

Check server:

```bash
adb shell ps -A | grep frida
```

Expected:

```text
frida-server
```

Check connection:

```bash
frida-ps -U
```

Expected:

```text
PID    Name
...
```

---

# 2. APK Recon

## 2.1 Identify File

```bash
file challenge.apk
```

Record:

```text
File type:
Size:
```

---

## 2.2 APK Contents

```bash
unzip -l challenge.apk
```

Cari native libraries:

```bash
unzip -l challenge.apk | grep '\.so'
```

Cari assets:

```bash
unzip -l challenge.apk | grep assets
```

Cari databases:

```bash
unzip -l challenge.apk | grep -Ei '\.db|sqlite'
```

Cari config:

```bash
unzip -l challenge.apk | grep -Ei 'json|xml|config'
```

---

# 3. JADX Static Analysis

Open:

```bash
jadx-gui challenge.apk
```

atau:

```bash
jadx -d source challenge.apk
```

---

# 4. AndroidManifest.xml

Buka:

```text
AndroidManifest.xml
```

Catat:

```text
Package:
Main Activity:
Other Activities:
Services:
Receivers:
Providers:
Permissions:
Exported components:
```

Cari:

```text
android:exported="true"
```

Command:

```bash
grep -Rni "exported" source/
```

---

# 5. Identify Entry Point

Cari:

```text
MAIN
LAUNCHER
```

Biasanya:

```xml
<intent-filter>
    <action android:name="android.intent.action.MAIN"/>
    <category android:name="android.intent.category.LAUNCHER"/>
</intent-filter>
```

Record:

```text
Main Activity:
```

---

# 6. Search Interesting Strings

Jangan hanya mencari `flag`.

Gunakan:

```bash
grep -RniE \
"flag|secret|password|passwd|token|key|admin|debug|check|verify|validate|decrypt|encrypt" \
source/
```

Tambahkan:

```bash
grep -RniE \
"base64|aes|des|rsa|xor|md5|sha|cipher|digest" \
source/
```

---

# 7. Static Analysis Strategy

Jangan membaca seluruh source code.

Gunakan:

```text
Entry Point
    ↓
User Input
    ↓
Validation
    ↓
Important Function
    ↓
Crypto / Storage / Network / Native
    ↓
Flag
```

---

# 8. Find User Input

Cari:

```text
EditText
Intent
Bundle
getStringExtra
SharedPreferences
HTTP request
ContentProvider
JNI
```

Contoh:

```java
String input =
    editText.getText().toString();
```

Catat:

```text
Input:
Variable:
Function:
```

---

# 9. Source → Transform → Sink

Gunakan format:

```text
SOURCE
  ↓
INPUT
  ↓
TRANSFORM
  ↓
VALIDATION
  ↓
SINK
```

Contoh:

```text
Intent.getStringExtra("password")
        ↓
decode()
        ↓
decrypt()
        ↓
equals()
        ↓
showFlag()
```

---

# 10. Crypto Identification

Cari:

```text
Cipher.getInstance()
MessageDigest.getInstance()
SecretKeySpec
IvParameterSpec
Base64.decode()
Base64.encode()
```

Contoh:

```java
Cipher cipher =
    Cipher.getInstance("AES/CBC/PKCS5Padding");
```

Record:

```text
Algorithm:
Mode:
Padding:
Key:
IV:
Input:
Output:
```

---

# 11. Decryption Analysis

## 11.1 Identify Cipher

Contoh:

```java
Cipher.getInstance(
    "AES/CBC/PKCS5Padding"
);
```

Berarti:

```text
Algorithm = AES
Mode      = CBC
Padding   = PKCS5Padding
```

---

# 12. Find the Key

Cari:

```text
SecretKeySpec
```

Contoh:

```java
byte[] key =
    "1234567890123456".getBytes();

SecretKeySpec keySpec =
    new SecretKeySpec(key, "AES");
```

Record:

```text
Key:
Encoding:
Length:
```

---

# 13. Find the IV

Cari:

```text
IvParameterSpec
```

Contoh:

```java
byte[] iv =
    "abcdefghijklmnop".getBytes();

IvParameterSpec ivSpec =
    new IvParameterSpec(iv);
```

Record:

```text
IV:
Encoding:
Length:
```

Kalau IV tidak ada:

```text
Mode mungkin ECB
```

tetapi **jangan berasumsi**. Konfirmasi dari source.

---

# 14. Determine Input Encoding

Sebelum decrypt, cari apakah ciphertext:

```text
Base64
Hex
Raw bytes
URL encoded
```

Contoh:

```java
byte[] data =
    Base64.decode(ciphertext, Base64.DEFAULT);
```

Flow:

```text
Ciphertext
 ↓
Base64 decode
 ↓
AES decrypt
 ↓
Plaintext
```

---

# 15. Base64 Decode

CLI:

```bash
echo 'SGVsbG8=' | base64 -d
```

Python:

```python
import base64

data = base64.b64decode("SGVsbG8=")

print(data)
print(data.decode())
```

---

# 16. Hex Decode

```python
data = bytes.fromhex(
    "48656c6c6f"
)

print(data)
print(data.decode())
```

Output:

```text
Hello
```

---

# 17. XOR

Kalau source:

```java
result[i] =
    data[i] ^ key[i % key.length];
```

Python:

```python
data = bytes.fromhex("...")
key = b"secret"

out = bytes(
    data[i] ^ key[i % len(key)]
    for i in range(len(data))
)

print(out)
```

---

# 18. AES Decryption Template

Install:

```bash
pip install pycryptodome
```

Jika environment Kali memakai PEP 668, gunakan:

```bash
python3 -m venv ~/crypto-env
source ~/crypto-env/bin/activate
pip install pycryptodome
```

Template:

```python
from Crypto.Cipher import AES
import base64

key = b"1234567890123456"
iv  = b"abcdefghijklmnop"

ciphertext = base64.b64decode(
    "PUT_CIPHERTEXT_HERE"
)

cipher = AES.new(
    key,
    AES.MODE_CBC,
    iv
)

plaintext = cipher.decrypt(ciphertext)

print(plaintext)
```

---

# 19. PKCS#7 Unpadding

AES-CBC biasanya menggunakan padding.

Gunakan:

```python
from Crypto.Util.Padding import unpad

plaintext = unpad(
    cipher.decrypt(ciphertext),
    AES.block_size
)

print(plaintext)
```

Complete:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

key = b"1234567890123456"
iv = b"abcdefghijklmnop"

ciphertext = base64.b64decode(
    "PUT_CIPHERTEXT_HERE"
)

cipher = AES.new(
    key,
    AES.MODE_CBC,
    iv
)

plaintext = unpad(
    cipher.decrypt(ciphertext),
    AES.block_size
)

print(plaintext.decode())
```

---

# 20. AES ECB Template

Kalau source menunjukkan:

```text
AES/ECB/PKCS5Padding
```

gunakan:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

key = b"1234567890123456"

ciphertext = base64.b64decode(
    "PUT_CIPHERTEXT_HERE"
)

cipher = AES.new(
    key,
    AES.MODE_ECB
)

plaintext = unpad(
    cipher.decrypt(ciphertext),
    AES.block_size
)

print(plaintext.decode())
```

---

# 21. AES GCM Template

Kalau:

```text
AES/GCM/NoPadding
```

perhatikan:

```text
key
nonce/IV
ciphertext
authentication tag
```

Template:

```python
from Crypto.Cipher import AES
import base64

key = b"PUT_KEY_HERE"

nonce = b"PUT_NONCE_HERE"

ciphertext = base64.b64decode(
    "PUT_CIPHERTEXT_HERE"
)

tag = base64.b64decode(
    "PUT_TAG_HERE"
)

cipher = AES.new(
    key,
    AES.MODE_GCM,
    nonce=nonce
)

plaintext = cipher.decrypt_and_verify(
    ciphertext,
    tag
)

print(plaintext.decode())
```

---

# 22. RSA Analysis

Cari:

```text
KeyFactory
Cipher.getInstance("RSA...")
PublicKey
PrivateKey
modulus
exponent
```

Jika challenge memberikan:

```text
n
e
c
```

jangan langsung menganggap bisa didecrypt.

Catat:

```text
n =
e =
c =
```

Kemudian analisis:

```text
Is n factorable?
Is p/q leaked?
Is e small?
Is padding used?
Is key reused?
```

---

# 23. Hash vs Encryption

Penting:

```text
MD5
SHA1
SHA256
```

adalah hash, bukan encryption.

Kalau source:

```java
MessageDigest.getInstance("SHA-256")
```

jangan mencari:

```text
decrypt SHA-256
```

Sebaliknya:

```text
input
 ↓
SHA-256
 ↓
digest
 ↓
compare
```

Cari apakah input dapat direcover atau brute-force dari ruang input yang kecil.

---

# 24. Dynamic Analysis Preparation

Install APK:

```bash
adb install challenge.apk
```

Check:

```bash
adb devices
```

Run:

```bash
adb shell monkey \
-p PACKAGE_NAME 1
```

---

# 25. Logcat

Clear:

```bash
adb logcat -c
```

Run application.

Monitor:

```bash
adb logcat
```

Filter:

```bash
adb logcat | grep -iE \
"flag|secret|password|error|exception|crypto"
```

---

# 26. Find Package Name

JADX:

```text
AndroidManifest.xml
```

atau:

```bash
adb shell pm list packages
```

Cari:

```bash
adb shell pm list packages | grep challenge
```

---

# 27. Frida Server Check

```bash
adb shell ps -A | grep frida
```

Harus ada:

```text
frida-server
```

Then:

```bash
frida-ps -U
```

Jika process list muncul:

```text
Frida connection = OK
```

---

# 28. Frida Application Discovery

```bash
frida-ps -Uai
```

Cari:

```bash
frida-ps -Uai | grep challenge
```

---

# 29. Frida Attach

```bash
frida -U -n com.example.challenge
```

Spawn:

```bash
frida -U -f com.example.challenge
```

Script:

```bash
frida -U -f com.example.challenge -l hook.js
```

---

# 30. Basic Frida Test

`test.js`:

```javascript
Java.perform(function () {

    console.log("[+] Frida attached!");

});
```

Run:

```bash
frida -U -f com.example.challenge -l test.js
```

Expected:

```text
[+] Frida attached!
```

---

# 31. Enumerate Classes

```javascript
Java.perform(function () {

    Java.enumerateLoadedClasses({

        onMatch: function(name) {

            if (name.includes("example")) {
                console.log(name);
            }

        },

        onComplete: function() {

            console.log("[+] Done");

        }

    });

});
```

---

# 32. Find Interesting Class

Suppose JADX gives:

```text
com.example.challenge.Crypto
```

Use:

```javascript
Java.perform(function () {

    var Crypto =
        Java.use(
            "com.example.challenge.Crypto"
        );

    console.log(
        Crypto.class.getDeclaredMethods()
    );

});
```

---

# 33. Hook Function

Suppose:

```java
String decrypt(String input)
```

Frida:

```javascript
Java.perform(function () {

    var Crypto =
        Java.use(
            "com.example.challenge.Crypto"
        );

    Crypto.decrypt
        .overload("java.lang.String")
        .implementation = function(input) {

            console.log(
                "[+] Input: " + input
            );

            var result =
                this.decrypt(input);

            console.log(
                "[+] Output: " + result
            );

            return result;
        };

});
```

---

# 34. Why Hook Crypto?

Static:

```text
encrypted value
```

Dynamic:

```text
decrypt(ciphertext)
       ↓
plaintext
```

So instead of manually reconstructing the algorithm:

```text
JADX
 ↓
find decrypt()
 ↓
Frida hook
 ↓
print plaintext
```

This is often much faster.

---

# 35. Hook Function Arguments

Example:

```javascript
Java.perform(function () {

    var Auth =
        Java.use(
            "com.example.challenge.Auth"
        );

    Auth.login.overload(
        "java.lang.String",
        "java.lang.String"
    ).implementation =
        function(username, password) {

            console.log(
                "[+] Username: " + username
            );

            console.log(
                "[+] Password: " + password
            );

            return this.login(
                username,
                password
            );
        };

});
```

---

# 36. Hook Return Value

```javascript
Java.perform(function () {

    var Auth =
        Java.use(
            "com.example.challenge.Auth"
        );

    Auth.isAdmin.implementation =
        function() {

            var result =
                this.isAdmin();

            console.log(
                "[+] isAdmin = " + result
            );

            return result;
        };

});
```

---

# 37. Runtime Bypass

Untuk challenge/lab, misalnya:

```java
boolean checkLicense() {
    return false;
}
```

Frida:

```javascript
Java.perform(function () {

    var App =
        Java.use(
            "com.example.challenge.App"
        );

    App.checkLicense.implementation =
        function() {

            console.log(
                "[+] checkLicense bypassed"
            );

            return true;
        };

});
```

Tujuan:

```text
Normal:
checkLicense()
 ↓
false
 ↓
blocked

Hook:
checkLicense()
 ↓
true
 ↓
continue
```

---

# 38. Intent Attack Surface

Manifest:

```xml
android:exported="true"
```

Source:

```java
String cmd =
    getIntent()
        .getStringExtra("cmd");
```

Flow:

```text
External Intent
      ↓
cmd
      ↓
function
      ↓
sensitive operation
```

Test dengan:

```bash
adb shell am start \
-n PACKAGE/.ActivityName \
--es cmd "test"
```

---

# 39. Activity Analysis Checklist

```text
[ ] exported?
[ ] permission?
[ ] authentication?
[ ] Intent extras?
[ ] data URI?
[ ] sensitive operation?
[ ] WebView?
[ ] file access?
```

---

# 40. Broadcast Receiver

Cari:

```text
<receiver>
```

Source:

```java
onReceive(
    Context context,
    Intent intent
)
```

Cari:

```text
getStringExtra()
getBooleanExtra()
getIntExtra()
```

Flow:

```text
Broadcast
 ↓
Receiver
 ↓
Input
 ↓
Sensitive function
```

---

# 41. Service

Cari:

```text
<service>
```

Analisis:

```text
onStartCommand()
onBind()
Binder
Intent extras
permissions
```

---

# 42. Content Provider

Cari:

```text
<provider>
```

Analisis:

```text
query()
insert()
update()
delete()
```

Pertanyaan:

```text
exported?
permission?
data accessible?
```

---

# 43. WebView

Cari:

```text
WebView
loadUrl
evaluateJavascript
addJavascriptInterface
setJavaScriptEnabled
```

Flow:

```text
Input
 ↓
URL
 ↓
WebView
 ↓
loadUrl()
```

Dynamic hook:

```javascript
Java.perform(function () {

    var WebView =
        Java.use("android.webkit.WebView");

    WebView.loadUrl
        .overload("java.lang.String")
        .implementation = function(url) {

            console.log(
                "[+] loadUrl: " + url
            );

            return this.loadUrl(url);
        };

});
```

---

# 44. Storage Analysis

Check:

```text
/data/data/PACKAGE/
```

Interesting:

```text
shared_prefs/
databases/
files/
cache/
```

Check package path:

```bash
adb shell pm path PACKAGE
```

Pull files when permissions allow:

```bash
adb pull REMOTE_PATH LOCAL_PATH
```

---

# 45. Native Library Analysis

Find:

```bash
unzip -l challenge.apk | grep '\.so'
```

Extract:

```bash
unzip challenge.apk -d extracted
```

Find:

```bash
find extracted -name "*.so"
```

---

# 46. Strings

```bash
strings libnative-lib.so
```

Search:

```bash
strings libnative-lib.so |
grep -Ei "flag|secret|password|key"
```

---

# 47. Ghidra

Open:

```bash
ghidra
```

Import:

```text
libnative-lib.so
```

Analyze:

```text
Functions
 ↓
JNI functions
 ↓
interesting function
 ↓
Decompiler
```

Look for:

```text
strcpy
strcat
sprintf
memcpy
gets
scanf
malloc
free
```

These are not automatically vulnerabilities; trace how their arguments are controlled.

---

# 48. JNI

JADX:

```java
public native String process(
    String input
);
```

This means:

```text
Java
 ↓
JNI
 ↓
Native .so
 ↓
C/C++
```

Find corresponding native implementation.

---

# 49. Native Frida

Find module:

```javascript
var module =
    Process.findModuleByName(
        "libnative-lib.so"
    );

console.log(module);
```

Find export:

```javascript
var addr =
    Module.findExportByName(
        "libnative-lib.so",
        "function_name"
    );

console.log(addr);
```

Hook:

```javascript
Interceptor.attach(addr, {

    onEnter: function(args) {

        console.log(
            "[+] Native function called"
        );

    },

    onLeave: function(retval) {

        console.log(
            "[+] Return: " + retval
        );

    }

});
```

---

# 50. Exploit Engineering

Setiap vulnerability harus dijelaskan:

```text
Vulnerability:
 
Source:

Attacker-controlled input:

Validation:

Sink:

Primitive:

Impact:

Exploit:

Result:
```

---

# 51. Example — Logic Bypass

```text
Vulnerability:
Client-side authentication check

Source:
User input

Validation:
isAdmin()

Sink:
showAdminPanel()

Primitive:
Runtime control over return value

Impact:
Access admin functionality

Exploit:
Frida hook isAdmin() → true

Result:
Admin panel accessible
```

---

# 52. Example — Intent Abuse

```text
Vulnerability:
Exported Activity

Source:
Intent extra

Input:
cmd

Validation:
None

Sink:
sensitiveFunction(cmd)

Primitive:
External control of cmd

Impact:
Sensitive operation

Exploit:
ADB am start with --es cmd
```

---

# 53. Example — Native Buffer Overflow

```text
Vulnerability:
Stack buffer overflow

Source:
User-controlled input

Sink:
strcpy()

Primitive:
Memory corruption

Impact:
Potential control-flow corruption

Next:
Determine offset
Check mitigations
Debug crash
Determine controllable state
Construct exploit
```

Do not jump directly from:

```text
strcpy()
```

to:

```text
RCE
```

First prove:

```text
Reachability
 ↓
Controllability
 ↓
Impact
```

---

# 54. Exploit Development Loop

```text
HYPOTHESIS
    ↓
TEST
    ↓
CRASH / OUTPUT
    ↓
OBSERVE
    ↓
REFINE
    ↓
RETEST
```

Example:

```text
Input 64 bytes
 ↓
normal

Input 100 bytes
 ↓
crash

Input 120 bytes
 ↓
different crash

Determine boundary
 ↓
debug
 ↓
determine control
```

---

# 55. Debugging Native Crash

Useful information:

```text
PC
SP
FP
registers
stack
backtrace
```

GDB:

```gdb
info registers
```

```gdb
bt
```

```gdb
x/20gx $sp
```

```gdb
disassemble
```

---

# 56. Binary Mitigation Check

```bash
checksec --file=libnative-lib.so
```

Record:

```text
RELRO:
Canary:
NX:
PIE:
```

Interpretation:

```text
Canary
→ stack corruption protection

NX
→ stack not executable

PIE
→ randomized binary base

RELRO
→ GOT/relocation protection
```

---

# 57. Network Analysis

Find:

```text
Retrofit
OkHttp
HttpURLConnection
WebView
URL
API endpoint
```

Search:

```bash
grep -RniE \
"http://|https://|api/|retrofit|okhttp" \
source/
```

Flow:

```text
APK
 ↓
HTTP request
 ↓
API
```

If required:

```text
Android
 ↓
Burp
 ↓
Server
```

---

# 58. Dynamic Network Observation

Record:

```text
Endpoint:
Method:
Headers:
Cookies:
Authorization:
Parameters:
Response:
```

Example:

```http
POST /api/login

username=test
password=test
```

Look for:

```text
JWT
token
ID
role
admin
debug
hidden endpoint
```

---

# 59. Final Exploit Documentation

Use:

```text
1. Vulnerability
2. Root cause
3. Source
4. Attacker-controlled input
5. Data flow
6. Sink
7. Primitive
8. Exploit method
9. Result
10. Flag
```

---

# 60. Full Mobile CTF Workflow

```text
                         APK
                          │
                          ▼
                       RECON
                          │
                          ▼
                       JADX
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
          Manifest      Java/Kotlin   Assets
             │            │            │
             └────────────┼────────────┘
                          ▼
                    Attack Surface
                          │
          ┌───────────────┼────────────────┐
          ▼               ▼                ▼
        Logic           Crypto           IPC
          │               │                │
          ▼               ▼                ▼
       Frida            Decode          Intent
          │               │                │
          └───────────────┼────────────────┘
                          ▼
                       Native?
                          │
                    ┌─────┴─────┐
                    ▼           ▼
                   NO          YES
                    │           │
                    │        Ghidra
                    │           │
                    │         Frida
                    │           │
                    └─────┬─────┘
                          ▼
                     Exploit
                          │
                          ▼
                         FLAG
```

---

# 61. Quick Checklist

## Static

```text
[ ] file APK
[ ] unzip APK
[ ] JADX
[ ] Manifest
[ ] Main Activity
[ ] exported components
[ ] strings
[ ] crypto
[ ] storage
[ ] network
[ ] native .so
```

## Dynamic

```text
[ ] adb devices
[ ] install APK
[ ] run APK
[ ] logcat
[ ] frida-server
[ ] frida-ps -U
[ ] identify package
[ ] attach/spawn
[ ] hook function
[ ] observe arguments
[ ] observe return
```

## Exploit

```text
[ ] identify source
[ ] identify attacker-controlled data
[ ] identify validation
[ ] identify sink
[ ] prove primitive
[ ] determine impact
[ ] construct exploit
[ ] retrieve flag
```

---

# 62. Write-Up Template

## Challenge

```text
Name:
Category:
Points:
```

## Recon

```text
APK:
Package:
Architecture:
```

## Static Analysis

```text
Interesting class:
Interesting method:
```

## Vulnerability

```text
Root cause:
```

## Data Flow

```text
SOURCE
 ↓
INPUT
 ↓
TRANSFORM
 ↓
VALIDATION
 ↓
SINK
```

## Dynamic Analysis

Command:

```bash
[COMMAND]
```

Frida script:

```javascript
[FRIDA SCRIPT]
```

Output:

```text
[OUTPUT]
```

## Exploit

```text
[STEPS]
```

## Result

```text
FLAG:
CTF{...}
```

## Root Cause

```text
[WHY THE APPLICATION WAS VULNERABLE]
```

---

# 63. Personal Cheat Sheet

```bash
# JADX
jadx-gui challenge.apk

# ADB
adb devices
adb install challenge.apk
adb shell
adb logcat

# Package
adb shell pm list packages
adb shell pm path PACKAGE

# Architecture
adb shell getprop ro.product.cpu.abi

# Frida
frida --version
adb shell ps -A | grep frida
frida-ps -U
frida-ps -Uai

# Attach
frida -U -n PACKAGE

# Spawn
frida -U -f PACKAGE

# Script
frida -U -f PACKAGE -l hook.js

# APK extraction
unzip challenge.apk -d extracted

# Native
find extracted -name "*.so"
strings libnative-lib.so

# Binary
checksec --file=libnative-lib.so
```

---

# 64. Golden Rules

```text
1. Jangan langsung exploit.
2. Pahami source → sink.
3. Jangan percaya hasil JADX 100%.
4. Kalau static cukup, jangan gunakan dynamic.
5. Gunakan Frida untuk observasi runtime.
6. Jangan menganggap crash = exploit.
7. Untuk crypto, identifikasi algorithm + mode + key + IV + encoding.
8. Hash bukan encryption.
9. Native .so → Ghidra.
10. Selalu buktikan primitive sebelum mengklaim impact.
11. Minimal payload > payload random.
12. Catat setiap command dan output.
```

---

# 65. One-Page Mental Model

```text
             WHAT DO I HAVE?
                    │
                    ▼
                   APK
                    │
                    ▼
              WHAT IS INSIDE?
                    │
                    ▼
                  JADX
                    │
                    ▼
            WHAT CAN I CONTROL?
                    │
          ┌─────────┼──────────┐
          ▼         ▼          ▼
        Intent     Input      Network
          │         │          │
          └─────────┼──────────┘
                    ▼
              WHERE DOES IT GO?
                    │
                    ▼
                  SINK
                    │
                    ▼
             IS IT VULNERABLE?
                    │
                    ▼
             PROVE THE PRIMITIVE
                    │
                    ▼
             DYNAMIC WITH FRIDA
                    │
                    ▼
               BUILD EXPLOIT
                    │
                    ▼
                  FLAG
```

---

# 66. Final Command Sequence

Untuk challenge baru:

```bash
# 1. Recon
file challenge.apk
unzip -l challenge.apk

# 2. Static
jadx-gui challenge.apk

# 3. Device
adb devices

# 4. Install
adb install challenge.apk

# 5. Run
adb shell monkey -p PACKAGE_NAME 1

# 6. Logs
adb logcat -c
adb logcat

# 7. Frida
adb shell ps -A | grep frida
frida-ps -U
frida-ps -Uai

# 8. Dynamic
frida -U -f PACKAGE_NAME -l hook.js

# 9. Native if needed
unzip challenge.apk -d extracted
find extracted -name "*.so"
strings extracted/lib/*/*.so

# 10. Document
# Source → Transform → Validation → Sink
# Primitive → Impact → Exploit → Flag
```

---

# 67. End Goal

Pada akhirnya, kamu harus bisa menjelaskan challenge seperti ini:

```text
APK
 ↓
MainActivity
 ↓
input dari Intent
 ↓
validation tidak memadai
 ↓
Crypto.decrypt()
 ↓
secret
 ↓
Frida hook
 ↓
recover plaintext
 ↓
bypass verification
 ↓
FLAG
```

Bukan hanya:

```text
"gue pakai Frida terus dapat flag"
```

Tetapi:

```text
"Ini root cause-nya.
Ini source input-nya.
Ini transformasinya.
Ini sink-nya.
Ini primitive yang saya dapat.
Ini kenapa exploit bekerja.
Ini command/script yang digunakan.
Dan ini flag-nya."
```

Itulah format **Mobile Reverse Engineering + Exploit Engineering** yang ideal untuk write-up CTF.
