import tkinter as tk
import sqlite3, os, hashlib, string, secrets, sys, random, math, csv, json
from pathlib import Path
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from base64 import urlsafe_b64encode, urlsafe_b64decode
from contextlib import closing
from datetime import datetime 

# ----------  SZYFRUJĄCY KLUCZ  ----------
master_key_bytes = None # 32-bajtowy klucz główny

DB_NAME_1 = "keys.db"
DB_NAME_2 = "catalogs.db"

# --- KONFIGURACJA ŚCIEŻEK ---
if os.name == 'nt':  # Windows
    base_dir = Path(os.getenv('LOCALAPPDATA'))
else:  # Linux / macOS
    base_dir = Path.home() / ".local" / "share"

data_dir = base_dir / "MH_Projekt" / "Adam"

#Tworzy folder, jeśli nie istnieje.
data_dir.mkdir(parents=True, exist_ok=True) 

db_path1 = data_dir / DB_NAME_1
db_path2 = data_dir / DB_NAME_2

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

setup_databases()

#Haszuje hasło używając pbkfd2
def _hash_password(password: str, salt: bytes) -> bytes:
    pwd_bytes = password.encode('utf-8')
    iterations = 100000 
    hash_bytes = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, iterations, dklen=32)
    return hash_bytes.hex()

#Sprawdza, czy podane hasło pasuje do zapisanego haszu
def _check_password(password: str, stored_hash: str, salt: bytes) -> bool:    
    new_hash = _hash_password(password, salt)
    return secrets.compare_digest(new_hash, stored_hash)

#Generuje i zwraca 32-bajtowy klucz KDF na podstawie hasła i soli
def _create_cipher(password: str, salt: bytes) -> bytes:
    #Przygotuje składniki
    pwd_bytes = password.encode('utf-8')
    iterations = 480000
    #Wygeneruje klucz KDF
    kdf = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, iterations, dklen=32)
    #Zwraca surowe bajty klucza
    return kdf

#Sprawdza, czy w bazie istnieje już hasło główne
def is_new_user() -> bool:
    try:
        with sqlite3.connect(db_path1) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ID FROM MasterKey WHERE ID = 1")
            result = cursor.fetchone()
            return result is None
    except sqlite3.Error:
        return True
   
#Ustawia hasło główne przy pierwszym uruchomieniu i loguje użytkownika
def set_initial_master_password(password: str):
    global master_key_bytes
    
    kdf_salt = os.urandom(16)
    new_hash = _hash_password(password, kdf_salt)
    try:
        with sqlite3.connect(db_path1) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO MasterKey (ID, hash, salt) VALUES (1, ?, ?)", (new_hash, kdf_salt))
            conn.commit()
            
        master_key_bytes = _create_cipher(password, kdf_salt)
        return True
    except sqlite3.Error as e:
        print(f"Błąd bazy danych: {e}")
        return False

#Uwierzytelnia użytkownika.
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

#Funkcja do generowania hasła
def generate_key(x, y, z):
    
    # x - ilość wszystkich znaków
    # y - ilość znaków specjalnych
    # z - hasło
    
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

#Oblicza entropię hasła i zwraca (opis_sily, kolor_hex).        
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

#Szyfruje hasło. Jeśli podano specific_key, używa go zamiast master_key_bytes.
def encrypt_password(pwd: str, specific_key=None) -> str:
    key = specific_key if specific_key else master_key_bytes
    
    if not key:
        raise ValueError("Błąd szyfrowania: Brak klucza (nie zalogowano lub brak klucza backupu)")

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, pwd.encode(), None)
    return urlsafe_b64encode(nonce + ciphertext).decode()   

#Deszyfruje hasło. Jeśli podano specific_key, używa go zamiast master_key_bytes.
def decrypt_password(enc_pwd: str, specific_key=None) -> str:
    key = specific_key if specific_key else master_key_bytes

    aesgcm = AESGCM(key)
    try:
        data_bytes = urlsafe_b64decode(enc_pwd.encode())
        nonce = data_bytes[:12]
        ciphertext = data_bytes[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception as e:
        print(f"KRYTYCZNY BŁĄD DESZYFROWANIA: {e}")
        return

#Funkcja do dodania klucza do bazy
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

#Funkcja do dodania katalogu do bazy    
def add_catalog(catalog):
    cat = catalog.get()
    if not cat:
        messagebox.showerror("Błąd", "Nazwa katalogu nie może być pusta!")
        return False

    try:
        with closing(get_connection()) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO Catalogs (Catalog) VALUES (?)", (cat,))
            conn.commit()
            
        messagebox.showinfo("Sukces", "Katalog dodany!")
        return True
    except sqlite3.IntegrityError:
        messagebox.showerror("Błąd", "Taki katalog już istnieje!")
        return False
    except Exception as e:
        messagebox.showerror("Błąd zapisu", f"Nie udało się zapisać katalogu: {e}")
        return False

#Funkcja do usunięcia katalogu z bazy    
def remove_catalog(catalog_id):
    cat = catalog_id
    try:
        with closing(get_connection()) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM Catalogs WHERE ID = ?", (cat,))
            conn.commit()
            
        messagebox.showinfo("Sukces", "Katalog usunięty.")
        return True
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się usunąć katalogu: {e}")
        return False
    
#Funkcja do usunięcia klucza z bazy
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

#Pobiera ID katalogu. Jeśli katalog nie istnieje, tworzy go automatycznie.    
def _get_catalog_id(catalog_name):
    try:
        with closing(get_connection()) as conn:
            cursor = conn.cursor()
            # Sprawdzamy, czy katalog istnieje w dołączonej bazie 'katalog'
            cursor.execute("SELECT ID FROM katalog.Catalogs WHERE Catalog = ?", (catalog_name,))
            result = cursor.fetchone()
            
            if result:
                return result[0]
            else:
                try:
                    cursor.execute("INSERT INTO katalog.Catalogs (Catalog) VALUES (?)", (catalog_name,))
                    conn.commit()
                    return cursor.lastrowid
                except sqlite3.Error as e:
                    print(f"Błąd przy dodawaniu katalogu: {e}")
                    return None
    except Exception as e:
        print(f"Błąd połączenia przy katalogach: {e}")
        return None
    
#Funkcja używana do importowania plików IMPORT
def add_entry_direct(wn, lg, passw, cat):
    if not cat:
        cat_id = None
    else:
        cat_id = _get_catalog_id(cat) 
        
    teraz = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        with sqlite3.connect(db_path1) as conn:
            cursor = conn.cursor()
            encrypted = encrypt_password(passw)
            cursor.execute("""
                INSERT INTO Keys (Web_Name, Login, Password, Catalog_ID, Date_Created, Date_Modified) 
                VALUES (?, ?, ?, ?, ?, ?)
            """, (wn, lg, encrypted, cat_id, teraz, teraz))
            conn.commit()
        return True
    except Exception as e:
        print(f"Błąd dodawania wpisu: {e}")
        return False

#Tworzy połączenie do głównej bazy ORAZ dołącza drugą bazę.
def get_connection():
    conn = sqlite3.connect(str(db_path1)) # pathlib Path trzeba zamienić na str dla starszych wersji
    
    conn.execute("PRAGMA foreign_keys = ON")
    
    try:
        conn.execute("ATTACH DATABASE ? AS katalog", (str(db_path2),))
    except sqlite3.OperationalError:
        pass
        
    return conn

#Pobiera połączone dane z obu baz do wyświetlenia w GUI.
def pobierz_dane_do_tabeli(fraza=None):
    try:
        with closing(get_connection()) as conn:
            conn.commit()
            cursor = conn.cursor()
            query = """
            SELECT 
                k.ID, 
                k.Web_Name, 
                k.Login, 
                IFNULL(c.Catalog, ' '),
                k.Password,
                k.Date_Created,
                k.Date_Modified
            FROM Keys k
            LEFT JOIN katalog.Catalogs c ON k.Catalog_ID = c.ID
            """
            
            #LOGIKA FILTROWANIA
            if fraza:
                query += " WHERE k.Web_Name LIKE ? OR k.Login LIKE ?"
                wzorzec = f"%{fraza}%"
                cursor.execute(query, (wzorzec, wzorzec))
            else:
                cursor.execute(query)
                
            return cursor.fetchall()
            
    except sqlite3.Error as e:
        print(f"Błąd pobierania danych: {e}")
        return []
    
def pobierz_katalogi():
    try:
        with closing(get_connection()) as conn:
            cursor = conn.cursor()
            query = """
            SELECT 
                ID, 
                Catalog
            FROM Catalogs
            """
            cursor.execute(query)
            return cursor.fetchall()
            
    except sqlite3.Error as e:
        print(f"Błąd pobierania danych: {e}")
        return []
    
#Pobiera listę wszystkich katalogów do GUI
def pobierz_liste_katalogow():
    try:
        with closing(get_connection()) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT Catalog FROM katalog.Catalogs ORDER BY Catalog ASC")
            # fetchall zwraca listę krotek np. [('Praca',), ('Dom',)], musimy to spłaszczyć
            return [row[0] for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"Błąd pobierania listy katalogów: {e}")
        return []

#NOWA FUNKCJA: Aktualizacja hasła konkretnego wpisu
def aktualizuj_haslo_wpisu(id_wpisu, nowe_haslo):
    try:
        teraz = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        encrypted = encrypt_password(nowe_haslo)
        
        with sqlite3.connect(db_path1) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE Keys SET Password = ?, Date_Modified = ? WHERE ID = ?", (encrypted, teraz, id_wpisu))
            conn.commit()
            
        return True, teraz
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się zaktualizować hasła: {e}")
        return False, None
    
    
def _change_master_password(old_pass, new_pass, new_pass_2):
    #Bezpiecznie zmienia hasło główne, ponownie szyfrując wszystkie dane
    global master_key_bytes
    
    #KROK 1: UWIERZYTELNIENIE I PRZYGOTOWANIE STAREGO KLUCZA ---
    with sqlite3.connect(db_path1) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT hash, salt FROM MasterKey WHERE ID = 1")
        result = cursor.fetchone()
        if not result:
            messagebox.showerror("Błąd krytyczny", "Nie znaleziono hasła głównego w bazie.")
            return

    master_hash, master_salt = result
    current_password = old_pass.get()
    
    if not _check_password(current_password, master_hash, master_salt):
        messagebox.showerror("Błąd", "Podane stare hasło jest nieprawidłowe.")
        return

    #Tworzymy stary klucz
    old_key_bytes = _create_cipher(current_password, master_salt)

    #KROK 2: POBRANIE NOWEGO HASŁA I STWORZENIE NOWEGO KLUCZA (AES-GCM) ---
    new_pass1 = new_pass.get()
    new_pass2 = new_pass_2.get()

    if not new_pass1 or new_pass1 != new_pass2:
        messagebox.showerror("Błąd", "Hasła są niezgodne lub puste.")
        return

    # Tworzymy składniki dla nowego hasła
    new_salt = os.urandom(16)
    new_hash = _hash_password(new_pass1, new_salt)
    new_key_bytes = _create_cipher(new_pass1, new_salt)

    #KROK 3: PONOWNE SZYFROWANIE DANYCH ---
    try:
        with sqlite3.connect(db_path1) as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT ID, Password FROM Keys")
            all_passwords = cursor.fetchall()

            for key_id, encrypted_pass in all_passwords:
                
                #Ustawia klucz globalny na stary, aby odszyfrować
                master_key_bytes = old_key_bytes
                decrypted_pass = decrypt_password(encrypted_pass) # Używa AES-GCM
                
                #Ustawia klucz globalny na nowy, aby zaszyfrować
                master_key_bytes = new_key_bytes
                reencrypted_pass = encrypt_password(decrypted_pass) # Używa AES-GCM
                
                #Zaktualizuje wiersz w bazie
                cursor.execute("UPDATE Keys SET Password = ? WHERE ID = ?", (reencrypted_pass, key_id))
            
            #KROK 4: ZAKTUALIZOWANIE HASŁA GŁÓWNEGO
            cursor.execute("UPDATE MasterKey SET hash = ?, salt = ? WHERE ID = 1", (new_hash, new_salt))
            
            #Globalny klucz jest już ustawiony na nowy
            messagebox.showinfo("Sukces", "Hasło główne zostało pomyślnie zmienione")

    except Exception as e:
        messagebox.showerror("Błąd krytyczny", f"Wystąpił krytyczny błąd podczas ponownego szyfrowania: {e}")
        #Przywraca stary klucz w sesji, jeśli coś poszło nie tak
        master_key_bytes = old_key_bytes
        
def wyczysc_dane_sesji():
    global master_key_bytes
    if master_key_bytes:
        #Nadpisujemy zmienną, aby utrudnić odczyt z pamięci RAM
        master_key_bytes = None

#Pobiera wszystkie dane z bazy i odszyfrowuje hasła
def get_all_decrypted_data():
    try:
        with closing(get_connection()) as conn:
            cursor = conn.cursor()
            query = """
            SELECT 
                k.Web_Name, 
                k.Login, 
                k.Password,
                IFNULL(c.Catalog, '')
            FROM Keys k
            LEFT JOIN katalog.Catalogs c ON k.Catalog_ID = c.ID
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            
            decrypted_data = []
            for row in rows:
                wn, lg, enc_pass, cat = row
                plain_pass = decrypt_password(enc_pass)
                decrypted_data.append({
                    "Strona": wn,
                    "Login": lg,
                    "Haslo": plain_pass,
                    "Katalog": cat
                })
            return decrypted_data
    except Exception as e:
        print(f"Błąd pobierania danych do eksportu: {e}")
        return []

#Funkcja do eksportowania CSV
def export_csv(filepath):
    data = get_all_decrypted_data()
    if not data:
        messagebox.showwarning("Pusto", "Brak danych do wyeksportowania.")
        return

    try:
        with open(filepath, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            # Nagłówki
            writer.writerow(["Strona", "Login", "Haslo", "Katalog"])
            for item in data:
                writer.writerow([item["Strona"], item["Login"], item["Haslo"], item["Katalog"]])
        messagebox.showinfo("Sukces", "Dane wyeksportowane do CSV (niezaszyfrowane!).")
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się zapisać pliku: {e}")

#Funkcja do importowania CSV
def import_csv(filepath):
    try:
        count = 0
        with open(filepath, mode='r', newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            try:
                header = next(reader)
            except StopIteration:
                pass

            for row in reader:
                if len(row) >= 3:
                    wn = row[0]
                    lg = row[1]
                    pw = row[2]
                    cat = row[3] if len(row) > 3 else ""
                    
                    if add_entry_direct(wn, lg, pw, cat):
                        count += 1
        return count
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się zaimportować pliku: {e}")
        return 0

#Funkcja do eksportowania zaszyfrowanego pliku
def export_encrypted(filepath, backup_password):
    data = get_all_decrypted_data()
    if not data:
        messagebox.showwarning("Pusto", "Brak danych do wyeksportowania.")
        return

    try:
        json_str = json.dumps(data)
        
        salt = os.urandom(16)
        backup_key = _create_cipher(backup_password, salt)        
        encrypted_blob = encrypt_password(json_str, specific_key=backup_key)

        final_content = {"salt_hex": salt.hex(),"data": encrypted_blob}
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(final_content, f)
            
        messagebox.showinfo("Sukces", "Wykonano zaszyfrowaną kopię zapasową.")
        
    except Exception as e:
        messagebox.showerror("Błąd", f"Błąd eksportu zaszyfrowanego: {e}")

#Funkcja do importowania zaszyfrowanego pliku
def import_encrypted(filepath, backup_password):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            file_content = json.load(f)
            
        salt_hex = file_content.get("salt_hex")
        encrypted_blob = file_content.get("data")
        
        if not salt_hex or not encrypted_blob:
            raise ValueError("Niepoprawny format pliku backupu.")
            
        salt = bytes.fromhex(salt_hex)
        backup_key = _create_cipher(backup_password, salt)
        
        json_str = decrypt_password(encrypted_blob, specific_key=backup_key)
        
        if json_str == "BŁĄD ODCZYTU HASŁA":
            messagebox.showerror("Błąd", "Nieprawidłowe hasło do pliku backupu!")
            return 0
            
        data = json.loads(json_str)
        count = 0
        for item in data:
            if add_entry_direct(item["Strona"], item["Login"], item["Haslo"], item["Katalog"]):
                count += 1
                
        return count
        
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się zaimportować: {e}")
        return 0
    
#Funkcja do testu roundtrip
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
