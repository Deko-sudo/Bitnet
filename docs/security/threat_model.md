# Model Ugroz (Threat Model)
## Menedzher parolei — Sistema bezopasnogo khraneniia dannykh

**Versiia:** 1.0  
**Data:** 8 marta 2026  
**Avtor:** Nikita (BE1 — Arkhitektor i spetsialist po bezopasnosti)

---

## 1. Vvedenie

### 1.1 Naznachenie dokumenta
Etot dokument opisivaet model ugroz dlia sistemy menedzhera parolei. Tsel — vyiavit potentsialnye ugrozy bezopasnosti, opredelit aktivy dlia zashchity i opisat kontrmery.

### 1.2 Oblast primeneniia
Dokument okhvatyvaet:
- Backend (Python FastAPI)
- Crypto Core (kriptograficheskoe iadro)
- Auth Manager (upravlenie autentifikatsiei)
- SQLite Database (SQLCipher)
- Audit Logger (logirovanie sobytii)

---

## 2. Aktivy (chto zashchishchaem)

### 2.1 Kriticheskie aktivy

| Aktiv | Opisanie | Kritichnost |
|-------|----------|-------------|
| **Master-parol** | Osnovnoi parol polzovatelia dlia dostupa k khranilishchu | KRITICHESKII |
| **Proizvodnye kliuchi** | Kliuchi shifrovaniia, poluchennye iz master-parolia | KRITICHESKII |
| **Zashifrovannye zapisi** | Loginy, paroli, zametki polzovatelei v BD | KRITICHESKII |
| **Sessionnye kliuchi** | Vremennye kliuchi aktivnoi sessii | VYSOKAIA |
| **Personalnye dannye** | Email, telefon, imia profilia | SREDNIAIA |
| **Audit log** | Zhurnal sobytii bezopasnosti | SREDNIAIA |
| **Konfiguratsiia bezopasnosti** | Parametry Argon2, soli, na stroiki | VYSOKAIA |

---

## 3. Atakuiushchie i stsenarii atak

### 3.1 Tipy atakuiushchikh

| Tip atakuiushchego | Vozmozhnosti | Motivatsiia |
|----------------|-------------|-----------|
| **Vneshni khaker** | Setevye ataki, ekspluatatsiia uiazvimostei | Finansovaia vygoda, dannye |
| **Zloumyshlennik s fiz. dostupom** | Dostup k ustroistvu, pamiati, disku | Krazha dannykh |
| **Insaider** | Dostup k kodu, logam, konfiguratsii | Sabotazh, shpionazh |
| **Avtomatizirovannye boty** | Brutofors, skanirovanie uiazvimostei | Massovye ataki |

### 3.2 Stsenarii atak

#### UC-1: Brutofors master-parolia
**Opisanie:** Atakuiushchii pytaetsia podobrat master-parol pereborom.  
**Vektor:** Login endpoint  
**Slozhnost:** Sredniaia  
**Vozdeistvie:** KRITICHESKOE — polnyi dostup ko vsem dannym

#### UC-2: SQL Injection
**Opisanie:** Vnedrenie vredonosnogo SQL-koda cherez vhodnye dannye.  
**Vektor:** API endpoints s parametrami  
**Slozhnost:** Nizkaia (esli net zashchity)  
**Vozdeistvie:** KRITICHESKOE — utechka BD

#### UC-3: Izvlechenie kliuchei iz pamiati
**Opisanie:** Chtenie operativnoi pamiati dlia polucheniia kliuchei shifrovaniia.  
**Vektor:** Fizicheskii dostup, cold boot attack  
**Slozhnost:** Vysokaia  
**Vozdeistvie:** KRITICHESKOE — rasshifrovka dannykh

#### UC-4: Perekhvat trafika (MITM)
**Opisanie:** Perekhvat dannykh mezhdu klientom i serverom.  
**Vektor:** Setevoe soedinenie  
**Slozhnost:** Sredniaia  
**Vozdeistvie:** VYSOKOE — krazha uchiotnykh dannykh

#### UC-5: Timing Attack
**Opisanie:** Analiz vremeni vypolneniia operatsii dlia polucheniia informatsii.  
**Vektor:** Sravnenie parolei, podpisei  
**Slozhnost:** Vysokaia  
**Vozdeistvie:** SREDNEE — utechka informatsii o kliuchakh

#### UC-6: Utechka cherez logi
**Opisanie:** Popadanie chuvstvitelnykh dannykh v logi prilozheniia.  
**Vektor:** Audit Logger, error logs  
**Slozhnost:** Nizkaia (oshibka razrabotki)  
**Vozdeistvie:** VYSOKOE — utechka parolei/kliuchei

---

## 4. Ugrozy i mery zashchity

### 4.1 Tablica ugroz (po STRIDE)

| Ugroza | Kategoriia STRIDE | Risk | Mery zashchity |
|--------|------------------|------|-------------|
| **Podbor master-parolia** | Spoofing | VYSOKII | Argon2id (t=3, m=64MB, p=4), Rate limiting |
| **Perekhvat dannykh** | Information Disclosure | VYSOKII | HTTPS/TLS 1.3, AES-256-GCM |
| **SQL Injection** | Tampering | VYSOKII | SQLAlchemy ORM, validatsiia cherez Pydantic |
| **Izvlechenie kliuchei iz pamiati** | Information Disclosure | SREDNII | zero_memory(), bytearray, avtoblokirovka |
| **Timing Attack** | Information Disclosure | NIZKII | constant_time_compare() |
| **Utechka cherez logi** | Information Disclosure | SREDNII | Pydantic SecretStr, AuditEventSchema validator |
| **DDoS** | Denial of Service | NIZKII | Rate limiting, request throttling |

### 4.2 Detalnoe opisanie mer zashchity

#### 4.2.1 Kriptograficheskaia zashchita

**Shifrovanie dannykh:**
- Algoritm: AES-256-GCM (rezhim AEAD)
- Kliuch: 256 bit, proizvodnyi cherez Argon2id
- nonce: 96 bit (unikalnyi dlia kazhdoi operatsii)
- Auth tag: 128 bit

**Derivatsiia kliuchei:**
- Funktsiia: Argon2id (pobeditel Password Hashing Competition)
- Parametry:
  - time_cost (t): 3 iteratsii
  - memory_cost (m): 64 MB
  - parallelism (p): 4 potoka
  - hash_len: 32 baita (256 bit)
- Sol: 128 bit, kriptostoikaia generatsiia (secrets.token_bytes)

#### 4.2.2 Zashchita ot brutoforsa

**Rate Limiter:**
```
Popytka 1-5: bez zaderzhki
Popytka 6-10: exponential backoff (1s, 2s, 4s, 8s, 16s)
Popytka 11+: blokirovka na 30 minut
```

#### 4.2.3 Zashchita pamiati

**zero_memory():**
- Obnulenie cherez ctypes.memset
- Ispolzovanie bytearray (mutabelnyi)

**MemoryGuard (context manager):**
```python
with MemoryGuard(master_key) as key:
    # rabota s kliuchom
# kliuch avtomaticheski obnulion
```

---

## 5. Arkhitekturnye riski

### 5.1 Edinye tochki otkaza (SPOF)

| Komponent | Risk | Mitigatsiia |
|-----------|------|-----------|
| SQLite Database | Povrezhdenie faila | Regulirnye bekapy, WAL rezhim |
| Master Password | Zabyt polzovatelem | Recovery codes (shifrovanie otdelno) |
| Crypto Core | Uiiazvimost v biblioteke | Regulirnyi audit, obnovlenie zavisimostei |

---

## 6. Cheklist bezopasnosti (Pre-Release)

### 6.1 Kod
- [ ] 0 kritichnykh zamechanii bandit
- [ ] 0 uiiazvimykh zavisimostei (safety check)
- [ ] Coverage >95% dlia crypto_core.py
- [ ] Vse sekrety cherez Pydantic SecretStr
- [ ] zero_memory() vyzyvaetsia dlia vsekh kliuchei

### 6.2 Testirovanie
- [ ] Penetration testing provedion
- [ ] SQL injection testy proideny
- [ ] Brutofors testy proideny

---

## 7. Glossarii

| Termin | Opredelenie |
|--------|-------------|
| **AEAD** | Authenticated Encryption with Associated Data |
| **Argon2id** | Gibridnaia funktsiia derivatsii kliuchei |
| **MITM** | Man-In-The-Middle — ataka posrednika |
| **SPOF** | Single Point of Failure — edinaia tochka otkaza |

---

**Dokument utverzhdon:**  
Nikita (BE1) — Arkhitektor bezopasnosti  
Data: 8 marta 2026
