# Menedżer haseł (Python + Tkinter)

## Opis projektu

Aplikacja jest graficznym **menedżerem haseł** napisanym w języku Python z wykorzystaniem biblioteki **Tkinter**. Program umożliwia bezpieczne przechowywanie danych logowania (strona, login, hasło), ich kategoryzowanie, generowanie silnych haseł oraz wykonywanie kopii zapasowych.

Hasła są **szyfrowane algorytmem AES-GCM**, a dostęp do aplikacji chroniony jest **hasłem głównym**, które nigdy nie jest przechowywane w postaci jawnej.

Projekt został wykonany jako aplikacja desktopowa.

---

## Funkcjonalności

* logowanie przy użyciu hasła głównego
* pierwsze uruchomienie z konfiguracją hasła głównego
* bezpieczne przechowywanie haseł (AES-GCM)
* generowanie losowych, silnych haseł
* ocena siły hasła na podstawie entropii
* katalogowanie wpisów (np. praca, bankowość, social media)
* edycja i usuwanie zapisanych haseł
* automatyczne czyszczenie schowka po skopiowaniu hasła
* zmiana hasła głównego z ponownym szyfrowaniem danych
* eksport i import danych:

  * CSV (niezaszyfrowany – ostrzeżenie bezpieczeństwa)
  * plik zaszyfrowany (backup z osobnym hasłem)

---

## Struktura projektu

* **MH_GUI.py** – główna aplikacja GUI (Tkinter)
* **fun.py** – logika aplikacji:

  * obsługa baz danych SQLite
  * szyfrowanie i deszyfrowanie haseł
  * generowanie i ocena haseł
  * import / eksport danych
* **keys.db** – baza danych z hasłami (tworzona automatycznie)
* **catalogs.db** – baza danych z katalogami (tworzona automatycznie)

---

## Bezpieczeństwo

* hasło główne jest haszowane algorytmem PBKDF2 (SHA-256 + sól)
* hasła użytkownika są szyfrowane algorytmem **AES-GCM**
* klucz szyfrujący tworzony jest dynamicznie z hasła głównego
* możliwość tworzenia zaszyfrowanych kopii zapasowych z osobnym hasłem
* automatyczne czyszczenie schowka po 30 sekundach

---

## Wymagania

* Python 3.10+
* biblioteki:

  * tkinter (standardowa biblioteka)
  * cryptography

Instalacja wymaganej biblioteki:

```bash
pip install cryptography
```

---

## Uruchomienie

1. Upewnij się, że pliki `MH_GUI.py` oraz `fun.py` znajdują się w tym samym katalogu
2. Uruchom aplikację poleceniem:

```bash
python MH_GUI.py
```

3. Przy pierwszym uruchomieniu ustaw hasło główne

---

## Autorzy

* Adam Borodin
* Tomasz Kowalczyk

---

## Zrzuty ekranu

1.Pierwsze uruchomienie-utworzenie hasła głównego

<img width="693" height="271" alt="Image" src="https://github.com/user-attachments/assets/f0912a75-d196-4f88-811c-c7b2008977aa" />

<br><br>

2.Ekran logowania

<img width="648" height="199" alt="Image" src="https://github.com/user-attachments/assets/69894d47-a8d6-46bb-9aa9-248500f3a284" />

<br><br> 

3.Menu główne

<img width="1350" height="553" alt="Image" src="https://github.com/user-attachments/assets/fdcabed3-7360-4071-ad8c-340a721dcc57" />

<br><br>

4.Dodawanie danych logowania

<img width="1061" height="391" alt="Image" src="https://github.com/user-attachments/assets/705696e1-f5a0-47cf-a3f7-b44f27f0e6a9" />

<br><br> 

5.Dane logowania

<img width="1025" height="446" alt="Image" src="https://github.com/user-attachments/assets/84136b93-07b1-4615-8b59-2ec7e59c411d" />

<br><br>

6.Dane wybranego klucza

<img width="1344" height="546" alt="Image" src="https://github.com/user-attachments/assets/810b964a-e90a-4665-8d0c-93347e054f53" />

<br><br>

7.Test roundtrip

<img width="309" height="167" alt="Image" src="https://github.com/user-attachments/assets/3eecf971-c4ae-4a47-bfeb-97e6ac9cecda" />

<br><Br>

8.Katalogi

<img width="1055" height="518" alt="Image" src="https://github.com/user-attachments/assets/c6667c2e-d3a2-46f3-9ae7-152bd19a8c2d" />

<br><br>

9.Zmiana hasła głównego

<img width="1056" height="512" alt="Image" src="https://github.com/user-attachments/assets/cd92503c-df58-4a3d-8e84-6c7a047b8d10" />

<br><br>

10.Kopia zapasowa

<img width="1050" height="521" alt="Image" src="https://github.com/user-attachments/assets/19bede23-a76e-48da-8eaf-526a1d501681" />

## Wymagania do projektu:
* Generowanie i przechowywanie master password (PBKDF2 z solą, 100k iteracji):
  
<img width="626" height="104" alt="Zrzut ekranu 2025-12-15 222907" src="https://github.com/user-attachments/assets/ac757fc3-a390-41e2-b80e-c70f513da056" />

<br><br>

* Baza danych SQLite:

<img width="762" height="855" alt="Zrzut ekranu 2025-12-15 223103" src="https://github.com/user-attachments/assets/160c96b1-57a7-41d4-b51f-13f8167c846b" />

<br><br>

* Funkcjonalność: dodawanie, usuwanie, wyświetlanie haseł:

<img width="1045" height="324" alt="Zrzut ekranu 2025-12-15 223241" src="https://github.com/user-attachments/assets/11ac2cfc-dcc6-45d1-9eb4-85f05e56d4f3" />
<img width="1304" height="512" alt="Zrzut ekranu 2025-12-15 223752" src="https://github.com/user-attachments/assets/ce22131a-457d-409a-a1f5-ad520c5130ba" />

<br><br>

* Obsługa błędów podstawowych (niepoprawne hasło):

<img width="817" height="202" alt="Zrzut ekranu 2025-12-15 223934" src="https://github.com/user-attachments/assets/f8598649-7c85-4723-a22f-2648e73f0e32" />

<br><br>

* Szyfrowanie AES-256-GCM:

```python
# Fragment pliku: fun.py
def encrypt_password(pwd: str, specific_key=None) -> str:
    key = specific_key if specific_key else master_key_bytes
    
    if not key:
        raise ValueError("Błąd szyfrowania: Brak klucza (nie zalogowano lub brak klucza backupu)")

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, pwd.encode(), None)
    return urlsafe_b64encode(nonce + ciphertext).decode()

