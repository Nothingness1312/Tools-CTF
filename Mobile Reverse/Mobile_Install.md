# Mobile CTF — APK to Android Analysis Workflow

Panduan praktis untuk memulai analisis APK Android dari kondisi:

```text
APK mentah
   ↓
Hubungkan Android / Emulator
   ↓
Install APK
   ↓
Identifikasi Package & Activity
   ↓
Jalankan APK
   ↓
Static Analysis dengan JADX
   ↓
Dynamic Analysis dengan ADB + logcat
   ↓
Dynamic Instrumentation dengan Frida
   ↓
Analisis Function / Crypto / Storage / IPC / Native
   ↓
Exploit Engineering
   ↓
FLAG
```

---

# 1. Environment

Environment yang digunakan:

```text
Host:
Windows

Linux:
Kali Linux WSL2

Android:
Android Emulator / Physical Device

Tools:
ADB
JADX
Frida
Python
Ghidra
apktool
```

Arsitektur umum:

```text
┌─────────────────────────────────────────┐
│               WINDOWS                   │
│                                         │
│        Android Studio Emulator          │
│              emulator-5554              │
│                  │                      │
└──────────────────┼──────────────────────┘
                   │
                   │ ADB
                   │
┌──────────────────▼──────────────────────┐
│               KALI WSL2                 │
│                                         │
│ JADX   ADB   Frida   Python   Ghidra   │
│                                         │
└─────────────────────────────────────────┘
```

---

# 2. Sebelum Mulai

Pastikan tools tersedia.

## 2.1 Check JADX

```bash
jadx --version
```

Contoh:

```text
1.5.5
```

GUI:

```bash
jadx-gui
```

---

# 3. Check ADB

```bash
adb --version
```

Kemudian:

```bash
adb devices
```

Expected:

```text
List of devices attached
emulator-5554    device
```

Status penting:

```text
device
```

Artinya perangkat sudah terhubung.

---

# 4. Jika Device Tidak Terdeteksi

Restart ADB:

```bash
adb kill-server
```

Kemudian:

```bash
adb start-server
```

Check:

```bash
adb devices
```

Jika menggunakan emulator:

```bash
adb devices
```

Expected:

```text
emulator-5554    device
```

---

# 5. Check Android Architecture

Gunakan:

```bash
adb shell getprop ro.product.cpu.abi
```

Contoh:

```text
x86_64
```

Informasi ini penting terutama jika APK mempunyai native library:

```text
.so
```

Misalnya:

```text
lib/arm64-v8a/
lib/armeabi-v7a/
lib/x86/
lib/x86_64/
```

Kalau emulator:

```text
x86_64
```

maka perhatikan apakah APK memiliki:

```text
lib/x86_64/
```

---

# 6. APK Recon Sebelum Install

Misalnya file:

```text
challenge.apk
```

Check:

```bash
ls -lh challenge.apk
```

Check tipe:

```bash
file challenge.apk
```

Expected:

```text
Android package (APK)
```

---

# 7. Lihat Isi APK

```bash
unzip -l challenge.apk
```

Jangan langsung membaca semuanya.

Cari bagian penting.

---

## 7.1 Cari Native Library

```bash
unzip -l challenge.apk | grep '\.so'
```

Contoh:

```text
lib/arm64-v8a/libnative.so
lib/x86_64/libnative.so
```

---

## 7.2 Cari Database

```bash
unzip -l challenge.apk | grep -Ei '\.db|sqlite'
```

---

## 7.3 Cari Asset

```bash
unzip -l challenge.apk | grep -i assets
```

---

## 7.4 Cari Config

```bash
unzip -l challenge.apk | grep -Ei \
'json|xml|config|properties'
```

---

# 8. Extract APK

Buat folder:

```bash
mkdir extracted
```

Extract:

```bash
unzip challenge.apk -d extracted
```

Lihat:

```bash
find extracted -maxdepth 2 -type f
```

Struktur umum:

```text
extracted/
├── AndroidManifest.xml
├── classes.dex
├── classes2.dex
├── resources.arsc
├── res/
├── assets/
├── lib/
└── META-INF/
```

---

# 9. Buka APK dengan JADX

Cara paling mudah:

```bash
jadx-gui challenge.apk
```

Atau output source:

```bash
jadx -d source challenge.apk
```

Kemudian:

```bash
find source -type f | head
```

---

# 10. AndroidManifest.xml

Ini adalah salah satu file pertama yang harus diperiksa.

Cari:

```text
AndroidManifest.xml
```

Informasi yang dicari:

```text
Package name
Main Activity
Activities
Services
Broadcast Receivers
Content Providers
Permissions
Exported components
Intent filters
Deep links
```

---

# 11. Menentukan Package Name

Contoh:

```xml
<manifest
    package="com.example.challenge">
```

Package:

```text
com.example.challenge
```

Simpan:

```text
PACKAGE=com.example.challenge
```

Untuk shell:

```bash
export PACKAGE=com.example.challenge
```

Kemudian bisa digunakan:

```bash
echo $PACKAGE
```

---

# 12. Cari Main Activity

Cari:

```xml
android.intent.action.MAIN
```

dan:

```xml
android.intent.category.LAUNCHER
```

Contoh:

```xml
<activity
    android:name=".MainActivity">

    <intent-filter>

        <action
            android:name="android.intent.action.MAIN"/>

        <category
            android:name="android.intent.category.LAUNCHER"/>

    </intent-filter>

</activity>
```

Maka:

```text
Main Activity:
.MainActivity
```

---

# 13. Cari Exported Component

Cari:

```bash
grep -Rni "exported" source/
```

Cari secara lebih luas:

```bash
grep -RniE \
"exported|permission|intent-filter" \
source/
```

Perhatikan:

```xml
android:exported="true"
```

Component yang exported dapat menjadi attack surface jika menerima input eksternal dan tidak melakukan validasi yang tepat.

Jangan langsung menganggap:

```text
exported=true
```

berarti vulnerable.

Tetap ikuti:

```text
Source
 ↓
Input
 ↓
Validation
 ↓
Sink
```

---

# 14. Setelah Static Recon, Install APK

Sekarang baru install.

```bash
adb install challenge.apk
```

Jika berhasil:

```text
Success
```

---

# 15. Jika APK Sudah Terinstall

Gunakan:

```bash
adb install -r challenge.apk
```

`-r` berarti reinstall/update aplikasi.

Jika ingin clean install:

```bash
adb uninstall com.example.challenge
```

Kemudian:

```bash
adb install challenge.apk
```

---

# 16. Verifikasi APK Terinstall

Cari package:

```bash
adb shell pm list packages | grep challenge
```

Contoh:

```text
package:com.example.challenge
```

Atau:

```bash
adb shell pm path com.example.challenge
```

Contoh:

```text
package:/data/app/.../base.apk
```

---

# 17. Jalankan APK

Cara umum:

```bash
adb shell monkey \
-p com.example.challenge \
1
```

Aplikasi akan dijalankan.

---

# 18. Menjalankan Activity Secara Langsung

Jika mengetahui:

```text
MainActivity
```

gunakan:

```bash
adb shell am start \
-n com.example.challenge/.MainActivity
```

Jika nama lengkap:

```bash
adb shell am start \
-n com.example.challenge/com.example.challenge.MainActivity
```

---

# 19. Melihat Activity yang Sedang Aktif

```bash
adb shell dumpsys activity activities | grep mResumedActivity
```

Contoh:

```text
mResumedActivity:
com.example.challenge/.MainActivity
```

Ini berguna ketika kita tidak tahu Activity mana yang sedang berjalan.

---

# 20. ADB Shell

Masuk ke Android:

```bash
adb shell
```

Sekarang command dijalankan di Android.

Contoh:

```bash
getprop ro.product.model
```

Keluar:

```bash
exit
```

---

# 21. Logcat

Sebelum menjalankan aplikasi:

```bash
adb logcat -c
```

Kemudian:

```bash
adb logcat
```

Sekarang interaksikan dengan aplikasi.

Misalnya:

```text
Open app
 ↓
Login
 ↓
Enter password
 ↓
Press button
```

Perhatikan output log.

---

# 22. Filter Logcat

Filter package:

```bash
adb logcat | grep -i "com.example.challenge"
```

Cari error:

```bash
adb logcat | grep -iE \
"error|exception|fatal"
```

Cari keyword:

```bash
adb logcat | grep -iE \
"flag|secret|password|token|key|crypto"
```

Cari crash:

```bash
adb logcat | grep -iE \
"FATAL EXCEPTION|AndroidRuntime"
```

---

# 23. Static Analysis Setelah APK Berjalan

Sekarang kembali ke JADX.

Jangan membaca seluruh source.

Gunakan pencarian.

Cari:

```text
flag
secret
password
token
admin
debug
check
verify
validate
decrypt
encrypt
crypto
key
```

Dengan CLI:

```bash
grep -RniE \
"flag|secret|password|token|admin|debug|check|verify|validate|decrypt|encrypt|crypto|key" \
source/
```

---

# 24. Cari Crypto

Cari:

```bash
grep -RniE \
"Cipher|getInstance|SecretKeySpec|IvParameterSpec|MessageDigest|Base64" \
source/
```

Perhatikan:

```java
Cipher.getInstance(...)
```

Misalnya:

```java
Cipher.getInstance(
    "AES/CBC/PKCS5Padding"
);
```

Catat:

```text
Algorithm:
AES

Mode:
CBC

Padding:
PKCS5Padding
```

---

# 25. Cari Key

Cari:

```text
SecretKeySpec
```

Contoh:

```java
SecretKeySpec keySpec =
    new SecretKeySpec(key, "AES");
```

Sekarang jangan berhenti di sini.

Follow variable:

```text
key
```

Cari dari mana key berasal.

Kemungkinan:

```text
Hardcoded
 ↓
String

User input
 ↓
Password

Function
 ↓
generateKey()

Storage
 ↓
SharedPreferences

Native
 ↓
JNI
```

---

# 26. Cari IV

Cari:

```text
IvParameterSpec
```

Contoh:

```java
IvParameterSpec iv =
    new IvParameterSpec(
        ivBytes
    );
```

Follow:

```text
ivBytes
```

Sama seperti key.

---

# 27. Tentukan Encoding Ciphertext

Ciphertext bisa berupa:

```text
Base64
Hex
Raw bytes
URL encoded
```

Cari:

```text
Base64.decode()
```

atau:

```text
bytes.fromhex()
```

atau kode encoding custom.

Flow harus dibuat seperti:

```text
Ciphertext
   ↓
Base64 Decode
   ↓
AES-CBC
   ↓
PKCS#7 Unpad
   ↓
Plaintext
```

---

# 28. Contoh Analisis Decryption

Misalnya source:

```java
String encrypted =
    "U2VjcmV0...";
```

Kemudian:

```java
byte[] data =
    Base64.decode(
        encrypted,
        Base64.DEFAULT
    );
```

Kemudian:

```java
Cipher cipher =
    Cipher.getInstance(
        "AES/CBC/PKCS5Padding"
    );
```

Kemudian:

```java
cipher.init(
    Cipher.DECRYPT_MODE,
    key,
    iv
);
```

Flow:

```text
encrypted
    ↓
Base64.decode()
    ↓
ciphertext bytes
    ↓
AES/CBC
    ↓
key + IV
    ↓
plaintext
```

---

# 29. Jangan Menebak Key

Kesalahan umum:

```text
"Kayaknya key = password"
```

Jangan asumsi.

Follow source:

```text
key
 ↓
where assigned?
 ↓
where returned?
 ↓
where transformed?
 ↓
where passed to Cipher?
```

---

# 30. Manual AES Decryption

Install dependency:

```bash
python3 -m venv ~/crypto-env
```

Activate:

```bash
source ~/crypto-env/bin/activate
```

Install:

```bash
pip install pycryptodome
```

Template:

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

# 31. Kalau Ciphertext Hex

Gunakan:

```python
ciphertext = bytes.fromhex(
    "001122334455..."
)
```

Bukan:

```python
base64.b64decode()
```

Pastikan mengikuti source aplikasi.

---

# 32. Dynamic Analysis

Static analysis menjawab:

```text
"Code-nya melakukan apa?"
```

Dynamic analysis menjawab:

```text
"Saat aplikasi berjalan, sebenarnya apa yang terjadi?"
```

Flow:

```text
JADX
 ↓
Temukan function
 ↓
Frida hook function
 ↓
Jalankan aplikasi
 ↓
Trigger function
 ↓
Lihat argument
 ↓
Lihat return value
```

---

# 33. Frida Server

Check:

```bash
adb shell ps -A | grep frida
```

Expected:

```text
frida-server
```

Kemudian:

```bash
frida-ps -U
```

Kalau muncul daftar process:

```text
Frida connection = OK
```

---

# 34. Cari APK di Frida

```bash
frida-ps -Uai | grep -i challenge
```

Contoh:

```text
12345   Challenge   com.example.challenge
```

---

# 35. Attach

Jika aplikasi sudah berjalan:

```bash
frida -U -n com.example.challenge
```

---

# 36. Spawn

Jika ingin Frida menjalankan aplikasi dari awal:

```bash
frida -U -f com.example.challenge
```

Lebih berguna ketika function penting dipanggil saat startup.

---

# 37. Frida Test Script

Buat:

```bash
nano test.js
```

Isi:

```javascript
Java.perform(function () {

    console.log(
        "[+] Frida attached!"
    );

});
```

Run:

```bash
frida -U \
-f com.example.challenge \
-l test.js
```

Expected:

```text
[+] Frida attached!
```

---

# 38. Enumerate Loaded Classes

```javascript
Java.perform(function () {

    Java.enumerateLoadedClasses({

        onMatch: function(name) {

            if (
                name.includes("example")
            ) {
                console.log(name);
            }

        },

        onComplete: function() {

            console.log(
                "[+] Enumeration complete"
            );

        }

    });

});
```

---

# 39. Hook Function

Misalnya JADX menemukan:

```java
public String decrypt(
    String input
)
```

Class:

```text
com.example.challenge.Crypto
```

Frida:

```javascript
Java.perform(function () {

    var Crypto =
        Java.use(
            "com.example.challenge.Crypto"
        );

    Crypto.decrypt
        .overload(
            "java.lang.String"
        )
        .implementation =
        function(input) {

            console.log(
                "[+] decrypt input: " +
                input
            );

            var result =
                this.decrypt(input);

            console.log(
                "[+] decrypt output: " +
                result
            );

            return result;
        };

});
```

Run:

```bash
frida -U \
-f com.example.challenge \
-l hook.js
```

Kemudian trigger function di aplikasi.

---

# 40. Apa yang Dicari dari Hook?

Misalnya output:

```text
[+] decrypt input:
U2FsdGVk...

[+] decrypt output:
CTF{example_flag}
```

Maka kita sudah mendapatkan:

```text
ciphertext
     ↓
decrypt()
     ↓
plaintext
```

Ini juga membantu memastikan apakah analisis static kita benar.

---

# 41. Hook Argument

Misalnya:

```java
login(
    String username,
    String password
)
```

Hook:

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
                "[+] username = " +
                username
            );

            console.log(
                "[+] password = " +
                password
            );

            return this.login(
                username,
                password
            );
        };

});
```

---

# 42. Hook Return Value

Misalnya:

```java
boolean isAdmin()
```

Hook untuk observasi:

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
                "[+] isAdmin = " +
                result
            );

            return result;
        };

});
```

Perhatikan bahwa tujuan awal dynamic analysis adalah **observasi**, bukan langsung bypass.

---

# 43. Storage Analysis

Cari package path:

```bash
adb shell pm path com.example.challenge
```

Untuk aplikasi sendiri/CTF yang environment-nya mengizinkan akses, periksa data:

```text
/data/data/com.example.challenge/
```

Directory penting:

```text
shared_prefs/
databases/
files/
cache/
```

---

# 44. SharedPreferences

Cari di JADX:

```text
SharedPreferences
getSharedPreferences
getString
putString
```

Contoh:

```java
SharedPreferences prefs =
    getSharedPreferences(
        "config",
        MODE_PRIVATE
    );
```

Cari:

```text
config
```

Kemudian lihat data yang disimpan.

---

# 45. SQLite

Cari:

```text
SQLiteDatabase
SQLiteOpenHelper
rawQuery
query
```

Database biasanya:

```text
databases/
```

Analisis:

```text
table
column
query
input
output
```

---

# 46. Intent Analysis

Cari:

```text
getIntent()
getStringExtra()
getParcelableExtra()
getBundleExtra()
```

Contoh:

```java
String command =
    getIntent()
        .getStringExtra("command");
```

Flow:

```text
External Intent
       ↓
command
       ↓
Function
       ↓
Sensitive Sink
```

---

# 47. Testing Exported Activity

Jika Activity memang exported dan challenge mengizinkan pengujian tersebut:

```bash
adb shell am start \
-n com.example.challenge/.AdminActivity
```

Jika membutuhkan extra:

```bash
adb shell am start \
-n com.example.challenge/.AdminActivity \
--es command "test"
```

Periksa hasil di aplikasi dan logcat.

---

# 48. Broadcast Receiver

Cari:

```text
<receiver>
```

dan:

```java
onReceive()
```

Cari input:

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
Validation
    ↓
Sensitive Function
```

---

# 49. Service

Cari:

```text
<service>
```

Kemudian:

```text
onStartCommand()
onBind()
Binder
Intent
```

Pertanyaan:

```text
Apakah service exported?
Apakah permission diperlukan?
Apakah input dapat dikontrol?
Apakah terdapat sensitive operation?
```

---

# 50. Content Provider

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

Perhatikan:

```text
exported
permission
URI
input
SQL query
sensitive data
```

---

# 51. WebView

Cari:

```text
WebView
loadUrl()
evaluateJavascript()
addJavascriptInterface()
setJavaScriptEnabled()
```

Flow:

```text
Attacker-controlled input
        ↓
URL
        ↓
WebView
        ↓
JavaScript / Native Bridge
```

Dynamic hook:

```javascript
Java.perform(function () {

    var WebView =
        Java.use(
            "android.webkit.WebView"
        );

    WebView.loadUrl
        .overload(
            "java.lang.String"
        )
        .implementation =
        function(url) {

            console.log(
                "[+] loadUrl = " +
                url
            );

            return this.loadUrl(
                url
            );
        };

});
```

---

# 52. Native Library

Cari:

```bash
unzip -l challenge.apk | grep '\.so'
```

Extract:

```bash
unzip challenge.apk -d extracted
```

Cari:

```bash
find extracted -name "*.so"
```

Contoh:

```text
extracted/lib/x86_64/libnative.so
```

---

# 53. Static Native Analysis

Strings:

```bash
strings extracted/lib/x86_64/libnative.so
```

Cari:

```bash
strings extracted/lib/x86_64/libnative.so \
| grep -Ei \
"flag|secret|password|key"
```

Kemudian buka di Ghidra.

---

# 54. JNI Analysis

Misalnya JADX:

```java
public native String decrypt(
    String input
);
```

Artinya Java memanggil native code.

Flow:

```text
Java
 ↓
JNI
 ↓
libnative.so
 ↓
C/C++
```

Cari implementasi native function di Ghidra.

---

# 55. Native Dynamic Analysis

Frida:

```javascript
var module =
    Process.findModuleByName(
        "libnative.so"
    );

console.log(module);
```

Cari export:

```javascript
var addr =
    Module.findExportByName(
        "libnative.so",
        "function_name"
    );

console.log(addr);
```

Hook:

```javascript
Interceptor.attach(
    addr,
    {

        onEnter: function(args) {

            console.log(
                "[+] native function called"
            );

        },

        onLeave: function(retval) {

            console.log(
                "[+] return = " +
                retval
            );

        }

    }
);
```

---

# 56. Source → Sink Analysis

Ini adalah konsep utama.

Selalu buat flow:

```text
SOURCE
   ↓
ATTACKER CONTROLLED INPUT
   ↓
TRANSFORMATION
   ↓
VALIDATION
   ↓
SINK
   ↓
IMPACT
```

Contoh:

```text
Intent.getStringExtra()
        ↓
"command"
        ↓
decode()
        ↓
NO VALIDATION
        ↓
executeCommand()
        ↓
Sensitive operation
```

---

# 57. Exploit Engineering

Setelah menemukan vulnerability, jangan langsung menyebutnya exploit.

Gunakan:

```text
Vulnerability
      ↓
Primitive
      ↓
Control
      ↓
Impact
      ↓
Exploit
```

Contoh:

```text
Exported Activity
      ↓
External Intent control
      ↓
Control "command"
      ↓
Sensitive function reached
      ↓
Exploit
```

---

# 58. Contoh Kasus Crypto

Static:

```text
MainActivity
 ↓
checkPassword()
 ↓
decrypt()
 ↓
AES/CBC
 ↓
compare()
```

Dynamic:

```text
Frida
 ↓
hook decrypt()
 ↓
input ciphertext
 ↓
output plaintext
```

Kemudian:

```text
Plaintext
 ↓
Understand verification
 ↓
Determine expected value
 ↓
Build solution
```

---

# 59. Contoh Kasus Authentication

Static:

```text
login()
 ↓
verifyPassword()
 ↓
isAdmin()
 ↓
showAdmin()
```

Dynamic:

```text
Hook verifyPassword()
 ↓
lihat input
 ↓
lihat return
```

Kemudian pahami apakah vulnerability-nya:

```text
Hardcoded credential
Client-side-only check
Weak comparison
Predictable token
Broken logic
```

---

# 60. Contoh Kasus Native

Static:

```text
Java
 ↓
native process()
 ↓
libnative.so
 ↓
buffer operation
```

Analisis:

```text
Input
 ↓
Native function
 ↓
Memory operation
 ↓
Crash / corruption
```

Kemudian buktikan:

```text
Reachability
 ↓
Controllability
 ↓
Impact
```

Jangan menganggap:

```text
Crash = RCE
```

---

# 61. Exploit Documentation Template

Gunakan template berikut:

```markdown
## Vulnerability

### Root Cause

[Explain the vulnerability]

### Source

[Where attacker-controlled data comes from]

### Attacker Controlled Input

[Exact parameter / Intent / network input]

### Transformation

[Decoding / encryption / parsing / conversion]

### Validation

[Validation performed by application]

### Sink

[Where the input eventually goes]

### Primitive

[What attacker can control]

### Impact

[What this control provides]

### Exploit

[Exact exploitation steps]

### Result

[Output / flag]
```

---

# 62. Investigation Notes Template

Setiap challenge buat file:

```text
notes.md
```

Isi:

```markdown
# Challenge

Name:

APK:

Package:

Architecture:

---

# Static Analysis

## Manifest

Main Activity:

Exported Components:

Services:

Receivers:

Providers:

---

# Interesting Classes

1.

2.

3.

---

# Interesting Functions

1.

2.

3.

---

# Crypto

Algorithm:

Mode:

Padding:

Key:

IV:

Encoding:

---

# Storage

SharedPreferences:

Database:

Files:

---

# Network

Endpoint:

Method:

Headers:

Parameters:

---

# Native

Libraries:

JNI Functions:

Interesting Native Functions:

---

# Dynamic Analysis

## Frida

Process:

Hook:

Input:

Output:

---

# Vulnerability

Source:

Input:

Validation:

Sink:

Primitive:

Impact:

---

# Exploit

Steps:

---

# Flag

CTF{...}
```

---

# 63. Full Workflow — Dari Nol

Ketika mendapat:

```text
challenge.apk
```

jalankan:

## Step 1 — File Check

```bash
file challenge.apk
ls -lh challenge.apk
```

---

## Step 2 — APK Recon

```bash
unzip -l challenge.apk
```

---

## Step 3 — JADX

```bash
jadx-gui challenge.apk
```

---

## Step 4 — Manifest

Cari:

```text
Package
Main Activity
Exported
Permissions
Services
Receivers
Providers
```

---

## Step 5 — Search Source

```bash
grep -RniE \
"flag|secret|password|token|admin|check|verify|decrypt|encrypt|crypto" \
source/
```

---

## Step 6 — Connect Android

```bash
adb devices
```

---

## Step 7 — Install

```bash
adb install challenge.apk
```

---

## Step 8 — Verify

```bash
adb shell pm list packages | grep challenge
```

---

## Step 9 — Run

```bash
adb shell monkey \
-p com.example.challenge \
1
```

---

## Step 10 — Observe

```bash
adb logcat -c
adb logcat
```

---

## Step 11 — Start Frida

```bash
adb shell ps -A | grep frida
```

---

## Step 12 — Verify Frida

```bash
frida-ps -U
```

---

## Step 13 — Find Target

```bash
frida-ps -Uai | grep challenge
```

---

## Step 14 — Spawn

```bash
frida -U \
-f com.example.challenge
```

---

## Step 15 — Hook

```bash
frida -U \
-f com.example.challenge \
-l hook.js
```

---

## Step 16 — Trigger Function

Interaksikan dengan aplikasi.

```text
Button
 ↓
Login
 ↓
Decrypt
 ↓
Validation
```

---

## Step 17 — Analyze Output

```text
Input:
Output:
Return:
Exception:
```

---

## Step 18 — Build Exploit

```text
Vulnerability
 ↓
Primitive
 ↓
Control
 ↓
Impact
 ↓
Exploit
```

---

# 64. Decision Tree

Gunakan decision tree ini ketika stuck.

```text
                 APK
                  │
                  ▼
                JADX
                  │
                  ▼
        ┌── Interesting Code? ──┐
        │                       │
       YES                      NO
        │                       │
        ▼                       ▼
     Analyze                 Search strings
        │                       │
        ▼                       ▼
   Crypto / Logic / IPC     Assets / Native
        │                       │
        └──────────┬────────────┘
                   ▼
             Run Application
                   │
                   ▼
                Logcat
                   │
                   ▼
              Need Runtime?
                   │
             ┌─────┴─────┐
            YES           NO
             │             │
             ▼             │
           Frida           │
             │             │
             ▼             │
         Hook Function     │
             │             │
             └──────┬──────┘
                    ▼
               Find Source
                    │
                    ▼
                 Find Sink
                    │
                    ▼
               Prove Primitive
                    │
                    ▼
                  Exploit
                    │
                    ▼
                   FLAG
```

---

# 65. Static vs Dynamic

## Static

Gunakan ketika ingin tahu:

```text
Apa function-nya?
Apa algorithm-nya?
Apa key-nya?
Apa endpoint-nya?
Apa component-nya?
Apa source code-nya?
```

Tools:

```text
JADX
apktool
Ghidra
strings
grep
```

---

## Dynamic

Gunakan ketika ingin tahu:

```text
Apa nilai sebenarnya?
Apa argument sebenarnya?
Apa return value?
Function mana yang dipanggil?
Apa yang terjadi setelah button ditekan?
Apa plaintext setelah decrypt?
```

Tools:

```text
ADB
logcat
Frida
GDB
Burp
```

---

# 66. Prinsip Utama

Jangan bekerja seperti:

```text
APK
 ↓
random command
 ↓
random Frida hook
 ↓
random payload
```

Gunakan:

```text
APK
 ↓
RECON
 ↓
STATIC ANALYSIS
 ↓
HYPOTHESIS
 ↓
DYNAMIC ANALYSIS
 ↓
OBSERVATION
 ↓
VALIDATE HYPOTHESIS
 ↓
EXPLOIT ENGINEERING
 ↓
FLAG
```

---

# 67. Golden Checklist

## APK

```text
[ ] file
[ ] unzip -l
[ ] extract
[ ] JADX
```

## Manifest

```text
[ ] package
[ ] MainActivity
[ ] exported
[ ] permissions
[ ] activities
[ ] services
[ ] receivers
[ ] providers
```

## Code

```text
[ ] flag
[ ] secret
[ ] password
[ ] token
[ ] admin
[ ] check
[ ] verify
[ ] decrypt
[ ] encrypt
[ ] crypto
[ ] native
```

## Android

```text
[ ] adb devices
[ ] adb install
[ ] package verification
[ ] run application
[ ] dumpsys activity
[ ] logcat
```

## Frida

```text
[ ] frida-server
[ ] frida-ps -U
[ ] frida-ps -Uai
[ ] attach
[ ] spawn
[ ] hook function
[ ] hook argument
[ ] hook return
```

## Crypto

```text
[ ] algorithm
[ ] mode
[ ] padding
[ ] key
[ ] IV
[ ] encoding
[ ] ciphertext
[ ] plaintext
```

## Exploit

```text
[ ] source
[ ] attacker-controlled input
[ ] validation
[ ] sink
[ ] primitive
[ ] impact
[ ] exploit
[ ] flag
```

---

# 68. Quick Start — 10 Commands

Kalau lagi CTF dan butuh cepat:

```bash
file challenge.apk
```

```bash
unzip -l challenge.apk
```

```bash
jadx-gui challenge.apk
```

```bash
adb devices
```

```bash
adb install challenge.apk
```

```bash
adb shell pm list packages | grep challenge
```

```bash
adb shell monkey -p com.example.challenge 1
```

```bash
adb logcat
```

```bash
frida-ps -U
```

```bash
frida -U -f com.example.challenge -l hook.js
```

---

# 69. Final Mental Model

Tujuan akhirnya bukan sekadar bisa menjalankan APK.

Kamu harus bisa menjawab:

```text
1. APK ini package-nya apa?

2. Main Activity-nya apa?

3. Component apa yang exposed?

4. Input attacker masuk dari mana?

5. Input tersebut diproses oleh function apa?

6. Apakah input di-decode?

7. Apakah input di-encrypt/decrypt?

8. Key dan IV berasal dari mana?

9. Data tersebut akhirnya masuk ke sink apa?

10. Apakah ada vulnerability?

11. Apa primitive yang kita dapat?

12. Bagaimana membuktikannya dengan dynamic analysis?

13. Bagaimana exploit bekerja?

14. Apa impact-nya?

15. Di mana flag?
```

Mental model:

```text
                  APK
                   │
                   ▼
                 JADX
                   │
                   ▼
             Understand App
                   │
                   ▼
             Find Attack Surface
                   │
       ┌───────────┼────────────┐
       ▼           ▼            ▼
     Logic       Crypto        IPC
       │           │            │
       ▼           ▼            ▼
     Frida       Decrypt      Intent
       │           │            │
       └───────────┼────────────┘
                   ▼
             Source → Sink
                   │
                   ▼
              Vulnerability
                   │
                   ▼
                Primitive
                   │
                   ▼
                 Impact
                   │
                   ▼
                Exploit
                   │
                   ▼
                  FLAG
```

**Rule paling penting:**

> **Jangan mulai dari exploit. Mulai dari memahami APK.**

Kalau kamu tahu **source → data flow → sink**, biasanya langkah exploit-nya jauh lebih jelas.
