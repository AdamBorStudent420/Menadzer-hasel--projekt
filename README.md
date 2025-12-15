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

```python
# Fragment pliku: fun.py
def _hash_password(password: str, salt: bytes) -> bytes:
    pwd_bytes = password.encode('utf-8')
    iterations = 100000 
    hash_bytes = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, iterations, dklen=32)
    return hash_bytes.hex()
```
<br><br>

* Baza danych SQLite:

```python
# Fragment pliku: fun.py
def setup_databases():
    #Tworzy pliki baz danych i tabele, jeśli nie istnieją.
    try:
        with sqlite3.connect(db_path1) as conn:
            cursor = conn.cursor()
            #Tabela do przechowywania kluczy
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS Keys (
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    Web_Name TEXT NOT NULL,
                    Login TEXT NOT NULL,
                    Password TEXT NOT NULL,
                    Catalog_ID INTEGER,
                    Date_Created TEXT NOT NULL,
                    Date_Modified TEXT NOT NULL,
                    FOREIGN KEY(Catalog_ID) REFERENCES Catalogs(ID)
                );
            ''')
            
            #Tabela do przechowywania jednego haszu hasła głównego
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS MasterKey (
                    ID INTEGER PRIMARY KEY CHECK (ID = 1), -- Gwarantuje tylko jeden wiersz
                    hash TEXT NOT NULL,
                    salt BLOB NOT NULL
                );
            ''')
            
            #Druga baza danych - katalogi
            cursor.execute("ATTACH DATABASE ? AS katalog", (str(db_path2),))
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS katalog.Catalogs (
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    Catalog TEXT NOT NULL UNIQUE
                );
            ''')
            
            #Dodaje startowe katalogi jeśli tabela jest pusta
            cursor.execute("SELECT COUNT(*) FROM katalog.Catalogs")
            liczba_katalogow = cursor.fetchone()[0]
            
            #Jeśli 0, to znaczy że to świeża baza (lub użytkownik usunął wszystko)
            if liczba_katalogow == 0:
                domyslne_katalogi = ["Social Media", "Poczta E-mail", "Bankowość", "Praca", "Rozrywka"]
                for kat in domyslne_katalogi:
                    try:
                        cursor.execute("INSERT INTO katalog.Catalogs (Catalog) VALUES (?)", (kat,))
                    except sqlite3.IntegrityError:
                        pass
            conn.commit()

    except sqlite3.Error as e:
        print(f"Wystąpił krytyczny błąd podczas inicjalizacji bazy danych: {e}")
        sys.exit()
```
<br><br>

* Funkcjonalność: dodawanie, usuwanie, wyświetlanie haseł:

<img width="1045" height="324" alt="Zrzut ekranu 2025-12-15 223241" src="https://github.com/user-attachments/assets/11ac2cfc-dcc6-45d1-9eb4-85f05e56d4f3" />
<img width="1304" height="512" alt="Zrzut ekranu 2025-12-15 223752" src="https://github.com/user-attachments/assets/ce22131a-457d-409a-a1f5-ad520c5130ba" />

```python
# Fragment pliku: fun.py
def add_key(web_name, login, password, catalog):
    wn = web_name.get()
    lg = login.get()
    passw = password.get()
    cat = catalog.get()
    if not cat:
        cat_id = None
    else:
        cat_id = _get_catalog_id(cat) 
        
    teraz = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        with sqlite3.connect(db_path1) as conn:
            cursor = conn.cursor()
            encrypted = encrypt_password(passw)
            
            #Date_Created i Date_Modified na start są takie same
            cursor.execute("""
                INSERT INTO Keys (Web_Name, Login, Password, Catalog_ID, Date_Created, Date_Modified) 
                VALUES (?, ?, ?, ?, ?, ?)
            """, (wn, lg, encrypted, cat_id, teraz, teraz))
            
            conn.commit()
        messagebox.showinfo("Sukces", "Hasło dodane!")
        return True
    except Exception as e:
        messagebox.showerror("Błąd zapisu", f"Nie udało się zapisać hasła: {e}")
        return False
```
```python
# Fragment pliku: fun.py
def remove_key(ID): 
    try:
        with sqlite3.connect(db_path1) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM Keys WHERE ID = ?", (ID,))
            conn.commit()
            
        messagebox.showinfo("Sukces", "Klucz usunięty.")
        return True
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się usunąć klucza: {e}")
        return False
```
<br><br>

* Obsługa błędów podstawowych (niepoprawne hasło):

<img width="817" height="202" alt="Zrzut ekranu 2025-12-15 223934" src="https://github.com/user-attachments/assets/f8598649-7c85-4723-a22f-2648e73f0e32" />

```python
# Fragment pliku: MH_GUI.py
    def sprawdz_haslo(entry_widget, parent_window, login_window):
        password = entry_widget.get()
        
        if fun._authenticate_user(password):
            parent_window.deiconify()
            login_window.destroy()
        else:
            messagebox.showerror("Błąd", "Nieprawidłowe hasło.")
```
```python
# Fragment pliku: fun.py
def _authenticate_user(password: str) -> bool:
    global master_key_bytes
    master_hash = None
    master_salt = None
    
    #Pobiera hasz z bazy
    with sqlite3.connect(db_path1) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT hash, salt FROM MasterKey WHERE ID = 1")
        result = cursor.fetchone()
        if result:
            master_hash = result[0]
            master_salt = result[1]

    if _check_password(password, master_hash, master_salt):
        master_key_bytes = _create_cipher(password, master_salt)
        return True
    else:
        return False
```
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
```
* Generator silnych haseł:

<img width="1016" height="306" alt="Zrzut ekranu 2025-12-15 224715" src="https://github.com/user-attachments/assets/6da9a2ff-f0b2-435c-b38f-38419acdac4a" />

```python
# Fragment pliku: fun.py
def generate_key(x, y, z):    
    try:
        num = x.get()
        if not num:
            messagebox.showerror("Błąd", "Pole 'Ilość znaków' jest puste.")
            return
        num_int = int(num)
        if num_int <= 0:
            messagebox.showerror("Błąd", "Ilość znaków musi być większa od zera!")
            return
        
        num_spec = y.get()
        num_spec_int = int(num_spec)
        if num_spec_int < 0:
            messagebox.showerror("Błąd", "Ilość znaków specjalnych nie może być ujemna!")
            return
        if num_spec_int > num_int:
            messagebox.showerror(
                "Błąd", "Ilość znaków specjalnych nie może przekraczać całkowitej liczby znaków.")
            return
        
        #Litery i cyfry
        general_chars = string.ascii_letters + string.digits 
        
        #Znaki specjalne
        special_chars = string.punctuation
        
        password_list = ([secrets.choice(special_chars) for _ in range(num_spec_int)] + [secrets.choice(general_chars) for _ in range(num_int - num_spec_int)])
        
        #Bezpieczne mieszanie listy (SystemRandom używa systemowego źródła RNG)
        random.SystemRandom().shuffle(password_list)
        password = ''.join(password_list)
        
        z.delete(0, tk.END)
        z.insert(0, f"{password}")
    except ValueError:
        messagebox.showerror("Błąd", "W polu 'Ilość znaków' musi być liczba!")
```

<br><br>

* Obsługa błędów rozszerzona (plik uszkodzony, bezpieczny logout):

<img width="355" height="212" alt="Zrzut ekranu 2025-12-15 224913" src="https://github.com/user-attachments/assets/1aed92e8-5afb-493c-9534-badd3b1f7b6b" />
```python
# Fragment pliku: MH_GUI.py
    def close_app(self, parent=None):
        target = parent if parent else self
        
        if messagebox.askokcancel("Zamknij", "Czy na pewno chcesz zamknąć aplikację?", parent=target):
            fun.wyczysc_dane_sesji()
            
            try:
                self.clipboard_clear()
            except tk.TclError:
                pass
            
            self.destroy()
            self.quit()
        else:
            pass
```
```python
# Fragment pliku: fun.py
def wyczysc_dane_sesji():
    global master_key_bytes
    if master_key_bytes:
        #Nadpisujemy zmienną, aby utrudnić odczyt z pamięci RAM
        master_key_bytes = None
```
<br><br>

* Szyfrowanie bazy danych (IV + salt przechowywane bezpiecznie):

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

def add_key(web_name, login, password, catalog):
    wn = web_name.get()
    lg = login.get()
    passw = password.get()
    cat = catalog.get()
    if not cat:
        cat_id = None
    else:
        cat_id = _get_catalog_id(cat) 
        
    teraz = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        with sqlite3.connect(db_path1) as conn:
            cursor = conn.cursor()
            encrypted = encrypt_password(passw)
            
            #Date_Created i Date_Modified na start są takie same
            cursor.execute("""
                INSERT INTO Keys (Web_Name, Login, Password, Catalog_ID, Date_Created, Date_Modified) 
                VALUES (?, ?, ?, ?, ?, ?)
            """, (wn, lg, encrypted, cat_id, teraz, teraz))
            
            conn.commit()
        messagebox.showinfo("Sukces", "Hasło dodane!")
        return True
    except Exception as e:
        messagebox.showerror("Błąd zapisu", f"Nie udało się zapisać hasła: {e}")
        return False
```
* Prosty GUI (Tkinter):

<img width="1340" height="551" alt="Zrzut ekranu 2025-12-15 225549" src="https://github.com/user-attachments/assets/afa7bd40-50b1-48d9-867f-a353e8ddf481" />

<br><br>

* Eksport/import haseł (CSV, format zaszyfrowany):

<img width="1340" height="551" alt="Zrzut ekranu 2025-12-15 225549" src="https://github.com/user-attachments/assets/15a892e5-d981-49ca-99ce-03999b0fc102" />

<br><br>

* Sprawdzenie siły hasła (entropy estimate:

<img width="547" height="31" alt="Zrzut ekranu 2025-12-15 225746" src="https://github.com/user-attachments/assets/e15e9162-7292-4b7f-b42a-0571c6c899cf" />
```python
# Fragment pliku: fun.py
def ocen_sile_hasla(password):
    if not password:
        return "Brak hasła", "#cccccc" #Szary

    #Określenie wielkości puli znaków
    pool_size = 0
    if any(c in string.ascii_lowercase for c in password): pool_size += 26
    if any(c in string.ascii_uppercase for c in password): pool_size += 26
    if any(c in string.digits for c in password): pool_size += 10
    if any(c in string.punctuation for c in password): pool_size += 32
    
    if pool_size == 0 and len(password) > 0:
        pool_size = 50 

    #Obliczenie entropii (w bitach)
    entropy = len(password) * math.log2(pool_size)

    #Klasyfikacja siły na podstawie bitów entropii
    if entropy < 28:
        return "Bardzo słabe hasło", "#ff3333" # Czerwony
    elif entropy < 36:
        return "Słabe hasło", "#ff9933"       # Pomarańczowy
    elif entropy < 60:
        return "Średnie hasło", "#ffff33"     # Żółty
    elif entropy < 128:
        return "Silne hasło", "#99ff33"       # Jasnozielony
    else:
        return "Bardzo silne hasło", "#33cc33" # Ciemnozielony
```

<br><br>

* Copy-to-clipboard (auto-clear po 30 sec):
```python
# Fragment pliku: MH_GUI.py
    def kopiuj_do_schowka(self, tekst, nazwa_pola="Dane"):
        if not tekst:
            return

        #Kopiowanie
        self.clipboard_clear()
        self.clipboard_append(tekst)
        self.update()
        
        #Zapamiętujemy, co skopiowaliśmy, aby później sprawdzić przy czyszczeniu
        self.ostatni_skopiowany_tekst = tekst
        
        #Anulowanie poprzedniego licznika (jeśli istnieje)
        if self.clipboard_timer:
            self.after_cancel(self.clipboard_timer)
            
        #Ustawienie nowego licznika na 30 sekund (30000 ms)
        self.clipboard_timer = self.after(30000, self.wyczysc_schowek)
        
    def wyczysc_schowek(self):
        try:
            #Pobieramy aktualną zawartość schowka
            aktualna_zawartosc = self.clipboard_get()
            
            #Czyścimy tylko wtedy, gdy w schowku nadal jest to samo hasło.
            #Jeśli użytkownik w międzyczasie skopiował coś innego, nie ruszamy tego.
            if aktualna_zawartosc == self.ostatni_skopiowany_tekst:
                self.clipboard_clear()
                
                #Nadpisujemy pustym stringiem (bezpieczniej dla Windows)
                self.clipboard_append("")
                
                #Wymuszamy aktualizację zdarzeń systemowych
                self.update()
                print("DEBUG: Schowek wyczyszczony automatycznie.")
            else:
                print("DEBUG: Zawartość schowka zmieniona przez użytkownika. Nie czyszczę.")
                
        except tk.TclError:
            pass
        finally:
            self.clipboard_timer = None
            self.ostatni_skopiowany_tekst = None
```

<br><br>

* Testy: roundtrip (szyfruj → odszyfruj → porównaj):
```python
# Fragment pliku: fun.py
def test_encryption_roundtrip(haslo):
    try:
        encrypted = encrypt_password(haslo)
        decrypted = decrypt_password(encrypted)
        if decrypted == haslo:
            messagebox.showinfo("Sukces", f"Mechanizm szyfrowania działa poprawnie.\n\nOryginał: {haslo}\nWynik deszyfrowania: {decrypted}")
        else:
            messagebox.showerror("Błąd", f"Odszyfrowana treść różni się od oryginału!\nOryginał: {haslo}\nWynik: {decrypted}")
    except Exception as e:

        messagebox.showerror("Błąd", f"WYJĄTEK PODCZAS TESTU: {str(e)}")
```
