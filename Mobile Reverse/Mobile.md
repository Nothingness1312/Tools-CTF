# 📱 Mobile Reverse Engineering CTF

## Kali WSL + Android Emulator + JADX + ADB + Frida

> Panduan lengkap untuk persiapan dan pengerjaan **Mobile Reverse Engineering CTF**, mulai dari static analysis APK sampai dynamic analysis menggunakan Frida.

---

# 1. Arsitektur Environment

Environment yang digunakan:

```text
┌─────────────────────────────────────────────────────────────┐
│                         WINDOWS                             │
│                                                             │
│  Android Studio / Android Emulator                          │
│       │                                                     │
│       │ emulator-5554                                      │
│       ▼                                                     │
│  ┌──────────────────────────────────────────────┐           │
│  │              Android Emulator               │           │
│  │                                              │           │
│  │  APK Challenge                               │           │
│  │  Android Runtime                             │           │
│  │  frida-server                                │           │
│  └──────────────────────┬───────────────────────┘           │
│                         │                                   │
└─────────────────────────┼───────────────────────────────────┘
                          │
                          │ ADB
                          │ Frida protocol
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                       KALI LINUX WSL                        │
│                                                             │
│  JADX GUI / CLI                                             │
│  ADB                                                        │
│  Frida Client                                               │
│  apktool                                                    │
│  Ghidra                                                     │
│  Python                                                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

Konsep sederhananya:

```text
JADX
 ↓
Membaca APK
 ↓
STATIC ANALYSIS


ADB
 ↓
Komunikasi dengan Android
 ↓
Install APK / shell / logcat / file


Frida
 ↓
Komunikasi dengan frida-server
 ↓
DYNAMIC ANALYSIS
 ↓
Hook function saat aplikasi berjalan
```

---

# 2. Static vs Dynamic Analysis

Ini konsep paling penting.

## Static Analysis

Static berarti:

> Menganalisis aplikasi **tanpa menjalankannya**.

Tool utama:

```text
JADX
apktool
Ghidra
strings
grep
```

Contoh:

```text
challenge.apk
      │
      ▼
     JADX
      │
      ▼
Java/Kotlin hasil decompile
      │
      ▼
Cari:
- password
- secret
- flag
- crypto
- validation
- API
```

---

## Dynamic Analysis

Dynamic berarti:

> Menganalisis aplikasi **ketika sedang berjalan**.

Tool utama:

```text
ADB
Frida
Burp Suite
logcat
```

Contoh:

```text
APK
 ↓
Android Emulator
 ↓
Application running
 ↓
Frida attach
 ↓
Hook function
 ↓
lihat argument
 ↓
lihat return value
```

---

# 3. APK Itu Sebenarnya Apa?

APK adalah package aplikasi Android.

Secara sederhana:

```text
challenge.apk
│
├── AndroidManifest.xml
├── classes.dex
├── resources.arsc
├── res/
├── assets/
├── lib/
│   ├── arm64-v8a/
│   └── x86_64/
└── META-INF/
```

Bagian penting untuk CTF:

### `AndroidManifest.xml`

Berisi informasi aplikasi:

```text
package
activities
services
receivers
permissions
exported components
```

### `classes.dex`

Berisi bytecode Dalvik/ART.

JADX membaca ini dan mencoba mengubahnya menjadi Java/Kotlin-like source code.

### `lib/*.so`

Native library.

Biasanya dibuat dengan:

```text
C
C++
Rust
```

Kalau challenge menggunakan native code, biasanya kita lanjut ke:

```text
Ghidra
IDA
Frida
```

### `assets/`

Kadang berisi:

```text
database
config
json
certificate
encrypted data
```

### `res/`

Resource Android:

```text
layout
strings
drawable
xml
```

---

# 4. JADX

JADX digunakan untuk melakukan **decompilation**.

## Cek instalasi

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

CLI:

```bash
jadx -d output challenge.apk
```

---

# 5. Membuka APK dengan JADX GUI

Jalankan:

```bash
jadx-gui
```

Kemudian:

```text
File
 ↓
Open
 ↓
challenge.apk
```

Setelah APK terbuka, biasanya akan terlihat:

```text
Sources
  └── com.example.challenge
       ├── MainActivity
       ├── LoginActivity
       ├── Utils
       └── Crypto
```

Jangan langsung membaca semua file.

Cari entry point terlebih dahulu.

---

# 6. AndroidManifest.xml

Hal pertama yang perlu dicek:

```text
AndroidManifest.xml
```

Cari:

```xml
<activity
    android:name=".MainActivity"
    android:exported="true">
```

Cari juga:

```text
android:exported="true"
```

Karena component exported dapat menjadi entry point yang menarik dalam beberapa challenge.

Cari:

```text
activity
service
receiver
provider
```

---

# 7. Recon dengan JADX

Jangan hanya mencari kata `flag`.

Gunakan search untuk:

```text
flag
secret
password
passwd
key
token
admin
debug
check
verify
validate
decrypt
encrypt
decode
encode
base64
aes
des
rsa
sha
md5
xor
```

Contoh:

```java
public boolean checkPassword(String input) {

    if (input.equals("Kucing123")) {
        return true;
    }

    return false;
}
```

Ini trivial.

Tapi challenge yang lebih bagus bisa seperti:

```java
public boolean checkPassword(String input) {

    String x = transform(input);

    return x.equals(expected);
}
```

Maka kita harus tracing:

```text
checkPassword()
      ↓
transform()
      ↓
decrypt()
      ↓
expected
```

---

# 8. Jangan Terlalu Percaya Hasil JADX

JADX adalah decompiler.

Decompiler **bukan source code asli**.

Misalnya bytecode:

```text
if-eqz
invoke-virtual
const-string
```

bisa diterjemahkan menjadi Java yang tidak sempurna.

Kalau source terlihat aneh:

```text
JADX
 ↓
Smali
```

Gunakan apktool untuk melihat representasi Smali.

---

# 9. APK Extraction

Kita juga bisa melihat isi APK:

```bash
unzip -l challenge.apk
```

Contoh:

```text
AndroidManifest.xml
classes.dex
resources.arsc
lib/x86_64/libnative-lib.so
assets/config.json
```

Kalau ada:

```text
lib/*.so
```

langsung catat.

Itu kemungkinan native challenge.

---

# 10. ADB

ADB = Android Debug Bridge.

ADB adalah tool komunikasi antara komputer dan Android.

Cek:

```bash
adb --version
```

Cek device:

```bash
adb devices
```

Target:

```text
List of devices attached
emulator-5554    device
```

Kalau status:

```text
offline
```

berarti device belum siap.

Kalau:

```text
unauthorized
```

biasanya perlu authorization.

---

# 11. Cek Android Device

Setelah:

```bash
adb devices
```

berhasil:

```bash
adb shell
```

Kamu akan masuk ke shell Android.

Contoh:

```text
generic_x86_64:/ $
```

Cek architecture:

```bash
adb shell getprop ro.product.cpu.abi
```

Contoh:

```text
x86_64
```

Informasi Android:

```bash
adb shell getprop ro.build.version.release
```

Package:

```bash
adb shell pm list packages
```

Cari:

```bash
adb shell pm list packages | grep example
```

---

# 12. Install APK

```bash
adb install challenge.apk
```

Kalau sudah ada versi sebelumnya:

```bash
adb install -r challenge.apk
```

Cek package:

```bash
adb shell pm list packages | grep challenge
```

---

# 13. Menjalankan APK

Misalnya package:

```text
com.example.challenge
```

Bisa menggunakan:

```bash
adb shell monkey -p com.example.challenge 1
```

Kemudian aplikasi akan dibuka.

---

# 14. Logcat

Logcat sangat berguna.

Basic:

```bash
adb logcat
```

Karena output banyak, gunakan:

```bash
adb logcat | grep -iE "error|exception|flag|secret|password"
```

Bersihkan log:

```bash
adb logcat -c
```

Kemudian jalankan aplikasi.

Setelah itu:

```bash
adb logcat
```

Kadang challenge membocorkan:

```text
DEBUG: decrypted = CTF{...}
```

---

# 15. Memeriksa File Application

Cari package path:

```bash
adb shell pm path com.example.challenge
```

Contoh:

```text
package:/data/app/~~abc==/com.example.challenge-xyz==/base.apk
```

Data aplikasi biasanya berada di:

```text
/data/data/com.example.challenge/
```

atau:

```text
/data/user/0/com.example.challenge/
```

Perhatikan:

```text
shared_prefs/
databases/
files/
cache/
```

Dalam CTF sering ada secret di:

```text
shared_prefs
database
files
```

---

# 16. SharedPreferences

Misalnya aplikasi menyimpan:

```text
token
username
secret
```

Secara konsep:

```text
shared_prefs/
└── app_preferences.xml
```

Jika permission memungkinkan:

```bash
adb shell
```

kemudian:

```bash
ls /data/data/com.example.challenge/
```

Pada emulator/rootable environment, kita mungkin bisa memeriksa:

```bash
cat /data/data/com.example.challenge/shared_prefs/*.xml
```

---

# 17. SQLite

Cari database:

```bash
find . -name "*.db"
```

atau dari device jika memiliki akses:

```bash
adb shell
find /data/data/com.example.challenge -type f
```

Misalnya:

```text
database/users.db
```

Pull:

```bash
adb pull /data/data/com.example.challenge/databases/users.db
```

Kemudian:

```bash
sqlite3 users.db
```

Di SQLite:

```sql
.tables
```

dan:

```sql
SELECT * FROM users;
```

---

# 18. Frida

Frida digunakan untuk:

> Dynamic instrumentation.

Artinya kita bisa memasukkan logic/instrumentation ke proses aplikasi saat aplikasi berjalan.

Konsep:

```text
Application
     │
     ▼
Function
     │
     ▼
Frida Hook
     │
     ├── lihat argument
     ├── lihat return value
     └── ubah behavior
```

---

# 19. Frida Client dan Server

Frida terdiri dari dua bagian penting.

## Kali

```text
frida-tools
frida
```

Ini adalah client.

Cek:

```bash
frida --version
```

Contoh:

```text
17.17.0
```

## Android

```text
frida-server
```

Ini berjalan di Android.

Contoh:

```text
/data/local/tmp/frida-server
```

Arsitektur:

```text
Kali
  │
  │ Frida protocol
  ▼
frida-server
  │
  ▼
Android process
```

---

# 20. Versi Frida Harus Diperhatikan

Client:

```bash
frida --version
```

Misalnya:

```text
17.17.0
```

Server sebaiknya:

```text
17.17.0
```

Jangan menggunakan:

```text
Client 17.17.0
Server 16.x
```

tanpa alasan.

---

# 21. Cek Architecture Android

```bash
adb shell getprop ro.product.cpu.abi
```

Contoh:

```text
x86_64
```

Maka Frida Server:

```text
frida-server-17.17.0-android-x86_64
```

Untuk:

```text
arm64-v8a
```

gunakan:

```text
frida-server-17.17.0-android-arm64
```

---

# 22. Install Frida Server

Download sesuai:

```text
version
architecture
```

Extract:

```bash
unxz frida-server-17.17.0-android-x86_64.xz
```

Rename:

```bash
mv frida-server-17.17.0-android-x86_64 frida-server
```

Permission:

```bash
chmod +x frida-server
```

Push:

```bash
adb push frida-server /data/local/tmp/frida-server
```

Output:

```text
1 file pushed
```

---

# 23. Jalankan Frida Server

```bash
adb shell chmod 755 /data/local/tmp/frida-server
```

Kemudian:

```bash
adb shell "/data/local/tmp/frida-server &"
```

Cek:

```bash
adb shell ps -A | grep frida
```

Target:

```text
shell ... frida-server
```

atau pada environment yang sesuai:

```text
root ... frida-server
```

---

# 24. Test Frida

Ini adalah pengecekan paling penting:

```bash
frida-ps -U
```

Jika berhasil:

```text
PID    Name
----   ------------------
4110   .adservices
3498   Chrome
3339   Files
1693   Settings
719    system_server
...
```

Maka:

```text
Frida Client
     ↓
ADB/device transport
     ↓
Frida Server
     ↓
Android processes
```

sudah berhasil.

---

# 25. Apa arti `-U`?

```bash
frida-ps -U
```

`-U` berarti menggunakan USB/device connection.

Dalam environment emulator yang terekspos melalui ADB, Frida dapat menggunakan device transport tersebut.

---

# 26. Cek aplikasi saja

Gunakan:

```bash
frida-ps -Uai
```

Ini membantu melihat aplikasi yang tersedia.

Cari package:

```bash
frida-ps -Uai | grep example
```

---

# 27. Attach ke Aplikasi

Misalnya:

```text
com.example.challenge
```

Jalankan dulu aplikasinya.

Kemudian:

```bash
frida -U -n com.example.challenge
```

atau menggunakan PID:

```bash
frida -U -p 1234
```

---

# 28. Spawn Application

Cara yang sering digunakan dalam CTF:

```bash
frida -U -f com.example.challenge
```

Artinya Frida menjalankan/spawn aplikasi dan attach sejak awal.

Ini penting untuk challenge yang memiliki:

```text
startup check
anti-debugging
root detection
initialization logic
```

---

# 29. Frida Script

Buat:

```bash
nano hook.js
```

Contoh paling dasar:

```javascript
Java.perform(function () {
    console.log("[+] Frida attached!");
});
```

Jalankan:

```bash
frida -U -f com.example.challenge -l hook.js
```

Jika berhasil:

```text
[+] Frida attached!
```

---

# 30. Enumerate Class

Untuk mencari class:

```javascript
Java.perform(function () {

    Java.enumerateLoadedClasses({
        onMatch: function (name) {

            if (name.includes("example")) {
                console.log(name);
            }

        },

        onComplete: function () {
            console.log("[+] Done");
        }
    });

});
```

Ini berguna kalau kita belum tahu class yang ingin di-hook.

---

# 31. Hook Java Method

Misalnya JADX menemukan:

```java
public boolean checkPassword(String input) {
    return input.equals("secret123");
}
```

Kita bisa hook:

```javascript
Java.perform(function () {

    var MainActivity =
        Java.use("com.example.challenge.MainActivity");

    MainActivity.checkPassword.implementation =
        function (input) {

            console.log("[+] Input: " + input);

            var result = this.checkPassword(input);

            console.log("[+] Result: " + result);

            return result;
        };

});
```

Jalankan:

```bash
frida -U -f com.example.challenge -l hook.js
```

Ketika function dipanggil:

```text
[+] Input: hello
[+] Result: false
```

---

# 32. Kenapa Dynamic Analysis Berguna?

Static memberi kita:

```text
"Function ini melakukan check."
```

Dynamic memberi kita:

```text
"Function ini benar-benar dipanggil."
"Argument-nya adalah X."
"Return value-nya Y."
```

Contoh:

```text
STATIC

checkPassword()
      ↓
menggunakan decrypt()
```

Dynamic:

```text
checkPassword("hello")
        ↓
decrypt("A83F...")
        ↓
"secret123"
        ↓
false
```

Kita mendapatkan informasi runtime.

---

# 33. Hook Return Value

Misalnya:

```java
boolean isPremium() {
    return false;
}
```

Untuk lab/CTF yang kamu analisis:

```javascript
Java.perform(function () {

    var App =
        Java.use("com.example.App");

    App.isPremium.implementation =
        function () {

            console.log("[+] isPremium called");

            return true;
        };

});
```

Ini contoh **runtime behavior modification**.

---

# 34. Hook Crypto

Misalnya JADX menemukan:

```java
String decrypt(String data)
```

Hook:

```javascript
Java.perform(function () {

    var Crypto =
        Java.use("com.example.Crypto");

    Crypto.decrypt.implementation =
        function (data) {

            console.log("[+] Encrypted: " + data);

            var result = this.decrypt(data);

            console.log("[+] Decrypted: " + result);

            return result;
        };

});
```

Output:

```text
[+] Encrypted: U2FsdGVk...
[+] Decrypted: CTF{example_flag}
```

Ini salah satu teknik paling berguna dalam Mobile Rev.

---

# 35. Overload

Java dapat memiliki:

```java
foo(String x)
foo(int x)
foo(String x, int y)
```

Frida harus memilih overload yang benar.

Contoh:

```javascript
var foo =
    App.foo.overload("java.lang.String");

foo.implementation = function (x) {

    console.log(x);

    return this.foo(x);
};
```

Kalau error:

```text
has more than one overload
```

cek overload terlebih dahulu.

---

# 36. Enumerate Methods

Kita bisa melihat method dari class:

```javascript
Java.perform(function () {

    var Cls =
        Java.use("com.example.challenge.MainActivity");

    console.log(
        Cls.class.getDeclaredMethods()
    );

});
```

Ini membantu mengetahui method yang tersedia.

---

# 37. Static + Dynamic Workflow

Workflow yang sangat efektif:

```text
                APK
                 │
        ┌────────┴─────────┐
        ▼                  ▼
     STATIC             DYNAMIC
        │                  │
      JADX                ADB
        │                  │
    Manifest            install
        │                  │
     Classes             run
        │                  │
      Logic             logcat
        │                  │
      Crypto            Frida
        │                  │
        └────────┬─────────┘
                 ▼
             EXPLOIT
                 │
                 ▼
               FLAG
```

---

# 38. Contoh Challenge

Misalnya diberikan:

```text
challenge.apk
```

Challenge mengatakan:

```text
Find the secret password.
```

---

## Step 1 — APK Recon

```bash
file challenge.apk
```

```bash
unzip -l challenge.apk
```

Cari native library:

```bash
unzip -l challenge.apk | grep '\.so'
```

---

# 39. Step 2 — JADX

```bash
jadx-gui challenge.apk
```

Cari:

```text
password
secret
check
verify
```

Misalnya ditemukan:

```java
public boolean verify(String input) {

    String decoded =
        Crypto.decrypt(DATA);

    return input.equals(decoded);
}
```

Sekarang kita tahu:

```text
verify()
 ↓
Crypto.decrypt()
 ↓
DATA
```

---

# 40. Step 3 — Static Crypto Analysis

Buka:

```text
Crypto.decrypt()
```

Misalnya:

```java
return new String(
    Base64.decode(data, 0)
);
```

Berarti secret mungkin hanya Base64.

Kita bisa decode:

```bash
echo 'SGVsbG8=' | base64 -d
```

Tetapi kalau lebih kompleks:

```text
AES
XOR
custom algorithm
native function
```

dynamic analysis lebih menarik.

---

# 41. Step 4 — Install APK

```bash
adb install challenge.apk
```

Cek:

```bash
adb devices
```

---

# 42. Step 5 — Run

```bash
adb shell monkey -p com.example.challenge 1
```

---

# 43. Step 6 — Logcat

```bash
adb logcat -c
```

Lakukan aksi di aplikasi.

Kemudian:

```bash
adb logcat | grep -iE "secret|password|flag|error"
```

---

# 44. Step 7 — Frida

Pastikan server:

```bash
adb shell ps -A | grep frida
```

Kemudian:

```bash
frida-ps -Uai | grep challenge
```

---

# 45. Step 8 — Hook

Misalnya class:

```text
com.example.challenge.Crypto
```

dan method:

```text
decrypt
```

Buat:

```javascript
Java.perform(function () {

    var Crypto =
        Java.use("com.example.challenge.Crypto");

    Crypto.decrypt.implementation =
        function (data) {

            console.log(
                "[+] decrypt input: " + data
            );

            var result = this.decrypt(data);

            console.log(
                "[+] decrypt output: " + result
            );

            return result;
        };

});
```

Run:

```bash
frida -U -f com.example.challenge -l hook.js
```

---

# 46. Cara Berpikir Saat Mengerjakan

Jangan berpikir:

> "Tool apa lagi yang harus aku install?"

Pikir:

> "Informasi apa yang belum aku ketahui?"

Contoh:

```text
Aku tahu function decrypt ada.
        ↓
Tapi aku tidak tahu inputnya.
        ↓
HOOK argument.
```

Atau:

```text
Aku tahu check() dipanggil.
        ↓
Tapi hasilnya selalu false.
        ↓
HOOK return value.
```

Atau:

```text
JADX tidak menunjukkan secret.
        ↓
Ada libnative.so.
        ↓
Analisis native dengan Ghidra.
```

---

# 47. Decision Tree Mobile Rev

```text
START
  │
  ▼
APK
  │
  ▼
JADX
  │
  ├── Secret langsung?
  │       │
  │       └── YES → FLAG
  │
  └── NO
       │
       ▼
   Trace logic
       │
       ├── Crypto?
       │      │
       │      └── analyze/decode
       │
       ├── Runtime value?
       │      │
       │      └── Frida
       │
       ├── Network?
       │      │
       │      └── Burp
       │
       ├── Native .so?
       │      │
       │      └── Ghidra + Frida
       │
       └── Storage?
              │
              ├── SharedPreferences
              ├── SQLite
              └── files
```

---

# 48. Troubleshooting ADB

## Device kosong

```bash
adb devices
```

hasil:

```text
List of devices attached
```

Cek emulator.

```bash
adb kill-server
adb start-server
adb devices
```

---

## Device offline

```text
emulator-5554    offline
```

Coba:

```bash
adb reconnect
```

atau:

```bash
adb kill-server
adb start-server
adb devices
```

---

# 49. Troubleshooting Frida

## `frida-ps -U` gagal

Pertama:

```bash
adb devices
```

Pastikan:

```text
emulator-5554    device
```

Kemudian:

```bash
adb shell ps -A | grep frida
```

Kalau kosong:

```text
frida-server tidak berjalan
```

Jalankan lagi:

```bash
adb shell "/data/local/tmp/frida-server &"
```

---

# 50. Version mismatch

Cek:

```bash
frida --version
```

dan server.

Pastikan:

```text
Client 17.17.0
Server 17.17.0
```

---

# 51. Architecture mismatch

Cek:

```bash
adb shell getprop ro.product.cpu.abi
```

Kalau:

```text
x86_64
```

gunakan:

```text
android-x86_64
```

Kalau:

```text
arm64-v8a
```

gunakan:

```text
android-arm64
```

---

# 52. SELinux Error

Kadang saat menjalankan:

```bash
adb shell "/data/local/tmp/frida-server &"
```

muncul:

```text
Unable to load SELinux policy from the kernel:
Permission denied
```

Jangan langsung menganggap Frida gagal.

Cek:

```bash
adb shell ps -A | grep frida
```

Kalau:

```text
shell ... frida-server
```

berarti process tetap berjalan.

Kemudian:

```bash
frida-ps -U
```

Jika process list muncul, **Frida sebenarnya sudah bekerja**.

---

# 53. Root vs Shell

Frida Server bisa berjalan sebagai:

```text
shell
```

atau:

```text
root
```

Untuk basic Java instrumentation:

```text
shell
```

bisa cukup.

Namun beberapa challenge membutuhkan:

```text
root privileges
```

misalnya:

```text
akses process tertentu
akses protected files
bypass tertentu
system-level instrumentation
```

Jangan menganggap semua challenge membutuhkan root.

---

# 54. Frida Attach vs Spawn

## Attach

Aplikasi sudah berjalan:

```bash
frida -U -n com.example.challenge
```

Bagus ketika:

```text
aplikasi sudah terbuka
function dipanggil setelah interaction
```

## Spawn

Frida menjalankan aplikasi:

```bash
frida -U -f com.example.challenge
```

Bagus ketika ingin menangkap:

```text
startup
initialization
anti-debug
root check
early crypto
```

---

# 55. Useful Frida Commands

List process:

```bash
frida-ps -U
```

List applications:

```bash
frida-ps -Uai
```

Attach by name:

```bash
frida -U -n com.example.app
```

Spawn:

```bash
frida -U -f com.example.app
```

Load script:

```bash
frida -U -f com.example.app -l hook.js
```

---

# 56. ADB Commands Cheat Sheet

```bash
adb devices
```

```bash
adb shell
```

```bash
adb install app.apk
```

```bash
adb uninstall com.example.app
```

```bash
adb install -r app.apk
```

```bash
adb shell pm list packages
```

```bash
adb shell pm path com.example.app
```

```bash
adb shell getprop ro.product.cpu.abi
```

```bash
adb shell getprop ro.build.version.release
```

```bash
adb shell monkey -p com.example.app 1
```

```bash
adb logcat
```

```bash
adb logcat -c
```

```bash
adb pull REMOTE LOCAL
```

```bash
adb push LOCAL REMOTE
```

---

# 57. JADX Cheat Sheet

Open GUI:

```bash
jadx-gui
```

Open APK:

```bash
jadx-gui challenge.apk
```

CLI:

```bash
jadx -d output challenge.apk
```

Search:

```bash
grep -RniE "flag|secret|password|token|key" output/
```

---

# 58. Frida Cheat Sheet

Check version:

```bash
frida --version
```

Check server:

```bash
adb shell ps -A | grep frida
```

Check connection:

```bash
frida-ps -U
```

Applications:

```bash
frida-ps -Uai
```

Attach:

```bash
frida -U -n PACKAGE
```

Spawn:

```bash
frida -U -f PACKAGE
```

Script:

```bash
frida -U -f PACKAGE -l hook.js
```

---

# 59. Recommended Directory Structure

Buat workspace:

```text
~/ctf/mobile/
│
├── challenge1/
│   ├── challenge.apk
│   ├── jadx/
│   ├── scripts/
│   │   ├── hook.js
│   │   └── enum.js
│   ├── extracted/
│   └── notes.md
│
├── challenge2/
│   └── ...
│
└── tools/
```

Contoh:

```bash
mkdir -p ~/ctf/mobile/challenge1/{scripts,extracted}
```

---

# 60. Checklist Sebelum CTF

## JADX

```bash
jadx --version
```

Target:

```text
1.5.x
```

---

## ADB

```bash
adb --version
```

Kemudian:

```bash
adb devices
```

Target:

```text
emulator-5554    device
```

---

## Android

```bash
adb shell getprop ro.product.cpu.abi
```

Catat:

```text
x86_64
```

atau architecture lain.

---

## Frida

```bash
frida --version
```

Target:

```text
17.17.0
```

Server:

```bash
adb shell ps -A | grep frida
```

---

## Frida Connection

```bash
frida-ps -U
```

Target:

```text
PID    Name
...
```

---

# 61. Final Workflow Saat Challenge Dimulai

Ketika panitia memberikan:

```text
challenge.apk
```

Jangan langsung menjalankan exploit.

Gunakan:

```text
                 APK
                  │
                  ▼
            unzip / file
                  │
                  ▼
                JADX
                  │
                  ▼
       AndroidManifest.xml
                  │
                  ▼
       Find interesting classes
                  │
                  ▼
        Trace important logic
                  │
       ┌──────────┼───────────┐
       ▼          ▼           ▼
     Crypto     Storage     Network
       │          │           │
       ▼          ▼           ▼
     Decode     SQLite       Burp
                  │
                  │
                  ▼
               Frida
                  │
          ┌───────┼────────┐
          ▼       ▼        ▼
        Input   Return   Runtime
          │       │        │
          └───────┼────────┘
                  ▼
             Vulnerability
                  │
                  ▼
                 FLAG
```

---

# 62. Mental Model

Mobile Reverse Engineering bukan:

```text
install 20 tools
 ↓
jalankan semua
 ↓
grep flag
```

Yang benar:

```text
OBSERVE
   ↓
UNDERSTAND
   ↓
HYPOTHESIS
   ↓
TEST
   ↓
OBSERVE AGAIN
   ↓
EXPLOIT
```

Contoh:

```text
JADX menunjukkan checkPassword()
        ↓
Hipotesis:
"password dibandingkan setelah decrypt"
        ↓
Frida hook decrypt()
        ↓
Lihat runtime argument + result
        ↓
Temukan secret
        ↓
Test secret
        ↓
FLAG
```

---

# 63. Prinsip Utama

### 1. Static dulu

Jangan langsung Frida jika source code sudah memberikan jawabannya.

### 2. Dynamic ketika informasi runtime dibutuhkan

Gunakan Frida untuk:

```text
argument
return value
runtime state
method call
crypto result
```

### 3. Native kalau `.so` muncul

```text
APK
 ↓
lib/*.so
 ↓
Ghidra
 ↓
Native function
 ↓
Frida
```

### 4. Network kalau aplikasi berbicara dengan server

```text
APK
 ↓
HTTP/HTTPS
 ↓
Burp
 ↓
API
```

### 5. Storage kalau aplikasi menyimpan data

```text
/data/data/
    ↓
shared_prefs
databases
files
cache
```

---

# 64. Environment Kamu Saat Ini

Berdasarkan setup yang sudah dilakukan:

```text
Kali Linux WSL2
│
├── JADX 1.5.5              ✅
├── ADB 34.0.5              ✅
├── Frida 17.17.0           ✅
└── Android Emulator        ✅
        │
        └── x86_64
              │
              └── frida-server 17.17.0 ✅
```

Test terakhir:

```bash
adb devices
```

harus:

```text
emulator-5554    device
```

dan:

```bash
frida-ps -U
```

harus menampilkan process Android.

Jika dua command tersebut berhasil, environment dasar **Mobile Reverse Engineering CTF** sudah siap.

---

# 65. Quick Start Saat Hari-H

Jika panitia memberikan:

```text
challenge.apk
```

jalankan:

```bash
mkdir challenge
cd challenge
cp /path/to/challenge.apk .
```

Static:

```bash
jadx-gui challenge.apk
```

Device:

```bash
adb devices
```

Install:

```bash
adb install challenge.apk
```

Run:

```bash
adb shell monkey -p PACKAGE_NAME 1
```

Log:

```bash
adb logcat -c
adb logcat
```

Frida:

```bash
adb shell ps -A | grep frida
```

```bash
frida-ps -U
```

Applications:

```bash
frida-ps -Uai
```

Spawn:

```bash
frida -U -f PACKAGE_NAME
```

Hook:

```bash
frida -U -f PACKAGE_NAME -l hook.js
```

---

# 66. Ringkasan Super Singkat

```text
JADX
=
"Bagaimana aplikasi ini bekerja?"

ADB
=
"Bagaimana aku berinteraksi dengan Android?"

Frida
=
"Apa yang sebenarnya terjadi ketika aplikasi berjalan?"

Ghidra
=
"Bagaimana native code ini bekerja?"

Burp
=
"Apa yang dikirim aplikasi ke server?"

SQLite
=
"Apa yang disimpan aplikasi?"

Logcat
=
"Apa yang aplikasi bocorkan saat runtime?"
```

Dan pola paling penting:

```text
             MOBILE REV
                  │
          ┌───────┴────────┐
          ▼                ▼
       STATIC           DYNAMIC
          │                │
        JADX              ADB
        APKTool          Frida
        Ghidra           logcat
          │                │
          └───────┬────────┘
                  ▼
              ANALYSIS
                  │
                  ▼
             EXPLOIT/BYPASS
                  │
                  ▼
                 FLAG
```
