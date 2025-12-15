import fun
import tkinter as tk
from tkinter import messagebox, ttk, filedialog, simpledialog, sys

# --- KLASA ODPOWIEDZIALNA ZA LOGOWANIE ---
class LoginManager:
    @staticmethod
    def login(parent_app):
        # SPRAWDZAMY, CZY TO PIERWSZE URUCHOMIENIE
        if fun.is_new_user():
            LoginManager.first_run_setup(parent_app)
        else:
            LoginManager.normal_login(parent_app)
            
    @staticmethod
    def normal_login(parent_app):
        def toggle_password(password, B1):
            if password.cget('show') == '*':
                password.config(show='')
                B1.config(text='Ukryj hasło')
            else:
                password.config(show='*')
                B1.config(text='Pokaż hasło')
                
        #Funkcja tworząca okno logowania.
        login_window = tk.Toplevel(parent_app)
        login_window.title("Weryfikacja")
        login_window.geometry("650x175")
        login_window.resizable(False, False)

        #Interfejs logowania
        tytul = tk.Label(login_window, font=("Consolas", 25), text="ZALOGUJ SIĘ")
        tytul.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

        logowanie_frame = ttk.LabelFrame(login_window, text=" Logowanie ")
        logowanie_frame.grid(row=1, column=0, padx=10, pady=10)
        
        wklej_token = tk.Label(logowanie_frame, text="Wpisz hasło główne")
        wklej_token.grid(row=0, column=0, padx=10, pady=10)
        
        text_token = tk.Entry(logowanie_frame, width=30, show="*")
        text_token.grid(row=0, column=1, padx=10, pady=10)
        
        text_token.bind('<Return>', lambda event: LoginManager.sprawdz_haslo(text_token, parent_app, login_window))
        
        B1 = tk.Button(logowanie_frame, text = "Pokaż hasło", width = 10, height=1, command=lambda: toggle_password(text_token, B1))
        B1.grid(row=0, column=2, padx=5, pady=10, sticky='w')
        
        zaloguj = tk.Button(logowanie_frame, text="Odblokuj", width=10, command=lambda: LoginManager.sprawdz_haslo(text_token, parent_app, login_window))
        zaloguj.grid(row=0, column=3, padx=10, pady=10)
        
        login_window.protocol("WM_DELETE_WINDOW", lambda: parent_app.close_app(parent=login_window))
        
        login_window.grab_set()
        parent_app.wait_window(login_window)
        
    @staticmethod
    #Okno wyświetlane tylko przy pierwszym uruchomieniu, do ustawienia hasła głównego.
    def first_run_setup(parent_app):
        setup_window = tk.Toplevel(parent_app)
        setup_window.title("Ustawienie hasła")
        setup_window.geometry("700x250")
        setup_window.resizable(False, False)
        
        tytul = tk.Label(setup_window, font=("Consolas", 20), text="PIERWSZE URUCHOMIENIE - UTWÓRZ HASŁO GŁÓWNE")
        tytul.grid(row=0, column=0, padx=10, pady=10)
        
        frame = ttk.Frame(setup_window)
        frame.grid(row=1, column=0, padx=10, pady=10)
        
        tk.Label(frame, text="Nowe hasło:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        e1 = tk.Entry(frame, show="*", width=30)
        e1.grid(row=2, column=1, padx=5, pady=5)
        
        tk.Label(frame, text="Powtórz hasło:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        e2 = tk.Entry(frame, show="*", width=30)
        e2.grid(row=3, column=1, padx=20, pady=5)
        
        def zatwierdz():
            p1 = e1.get()
            p2 = e2.get()
            
            if not p1:
                messagebox.showerror("Błąd", "Hasło nie może być puste.")
                return
            if p1 != p2:
                messagebox.showerror("Błąd", "Hasła nie są identyczne.")
                return
                
            # Ustawiamy hasło i logujemy
            if fun.set_initial_master_password(p1):
                messagebox.showinfo("Sukces", "Hasło główne zostało ustawione.")
                parent_app.deiconify()
                setup_window.destroy()
            else:
                return

        btn = tk.Button(setup_window, text="Zapisz hasło", width=15, command=zatwierdz)
        btn.grid(row=4, column=0, padx=5, pady=5)
        
        setup_window.grab_set()
        parent_app.wait_window(setup_window)

    @staticmethod
    def sprawdz_haslo(entry_widget, parent_window, login_window):
        password = entry_widget.get()
        
        if fun._authenticate_user(password):
            parent_window.deiconify()
            login_window.destroy()
        else:
            messagebox.showerror("Błąd", "Nieprawidłowe hasło.")

        
class App(tk.Tk): 
    def __init__(self):
        super().__init__()
        
        self.withdraw() #Ukrywa główne okno
        self.clipboard_timer = None #Zmienna do przechowywania timera schowka
        self.ostatni_skopiowany_tekst = None #Zmienna do sprawdzania zawartości schowka
        
        #Uruchomia logowanie
        LoginManager.login(self) 
        
        try:
            if not self.winfo_exists():
                sys.exit()
                
            if self.state() == 'withdrawn':
                self.destroy()
                sys.exit()
                
        except (tk.TclError, SystemExit):
            sys.exit()
            
        # --- BUDOWANIE INTERFEJSU PO ZALOGOWANIU ---        
        self.title("Program - Adam Borodin i Tomasz Kowalczyk - INFORMATYKA - ROK III NST")
        self.geometry("1350x530")
        self.minsize(1350, 530) 
        
        self.protocol("WM_DELETE_WINDOW", self.close_app)
        
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(1, weight=1)
        
        self.menu_glowne_tab()
        
        content_container = tk.Frame(self)
        content_container.grid(row=0, column=1, rowspan=2, sticky='nsew', padx=10, pady=5)
        content_container.grid_rowconfigure(0, weight=1)
        content_container.grid_columnconfigure(0, weight=1)
        
        self.frame_dane_logowania = self.dane_logowania_tab(content_container)
        self.frame_dodaj_dane = self.dodaj_dane_logowania_tab(content_container)
        self.frame_katalogi = self.katalogi_tab(content_container)
        self.frame_zmien_haslo_glowne = self.zmien_haslo_glowne_tab(content_container)
        self.frame_kopie = self.kopie_zapasowe_tab(content_container)

        self.frame_dane_logowania.grid(row=0, column=0, sticky='nsew')
        self.frame_dodaj_dane.grid(row=0, column=0, sticky='nsew')
        self.frame_katalogi.grid(row=0, column=0, sticky='nsew')
        self.frame_zmien_haslo_glowne.grid(row=0, column=0, sticky='nsew')
        self.frame_kopie.grid(row=0, column=0, sticky='nsew')

        #Pokauje domyślną ramkę na start
        self.pokaz_ramke("dane_logowania")
    
    #Funkcja, która sprawdza siłę hasła
    def aktualizuj_sile(self, password, lbl, event=None):
            try:
                haslo = password.get()
                wynik = fun.ocen_sile_hasla(haslo)

                if wynik and len(wynik) == 2:
                    tekst, kolor = wynik
                    lbl.config(text=tekst, bg=kolor, fg="black" if kolor != "#33cc33" else "white")
                else:
                    lbl.config(text="Błąd oceny", bg="grey")
            except Exception as e:
                print(f"Błąd w aktualizuj_sile: {e}")
                
    #Funkcja do przełączania widoków (ramek)
    def pokaz_ramke(self, nazwa_ramki):
        if hasattr(self, 'frame_klucz') and self.frame_klucz.winfo_exists():
            self.frame_klucz.destroy()
            self.frame_dane_logowania.grid(row=0, column=0, sticky='nsew')

        if nazwa_ramki == "dane_logowania":
            if not self.frame_dane_logowania.winfo_manager():
                self.frame_dane_logowania.grid(row=0, column=0, sticky='nsew')
            
            self.frame_dane_logowania.tkraise()
            self.wczytaj_dane_z_bazy()
            
        elif nazwa_ramki == "dodaj_dane":
            self.frame_dodaj_dane.tkraise()
            self.odswiez_liste_katalogow()
        elif nazwa_ramki == "katalogi":
            self.frame_katalogi.tkraise()
        elif nazwa_ramki == "zmien_haslo_glowne":
            self.frame_zmien_haslo_glowne.tkraise()
        elif nazwa_ramki == "kopie":
            self.frame_kopie.tkraise()
        
    def menu_glowne_tab(self):
        title = tk.Label(self, font = ("Consolas", 25), text="MENADŻER HASEŁ")
        title.grid(row=0, column=0, padx=10, pady=(10,0))
        
        F_1 = ttk.LabelFrame(self, text=" Menu główne ")
        F_1.grid(row=1, column=0, padx=10, pady=5, sticky='ns')
        FF_1 = ttk.Frame(F_1)
        FF_1.grid(row=1, column=0, padx=10, pady=5)
        
        B1 = tk.Button(FF_1, text = "Dane logowania", width = 30, height=1, command=lambda: self.pokaz_ramke("dane_logowania"))
        B1.grid(row=0, column=0, padx=10, pady=5)
        
        B2 = tk.Button(FF_1, text = "Dodaj dane logowania", width = 30, height=1, command=lambda: self.pokaz_ramke("dodaj_dane"))
        B2.grid(row=1, column=0, padx=10, pady=5)
        
        B3 = tk.Button(FF_1, text = "Katalogi", width = 30, height=1, command=lambda: self.pokaz_ramke("katalogi"))
        B3.grid(row=2, column=0, padx=10, pady=5)
        
        B4 = tk.Button(FF_1, text = "Zmień hasło główne", width = 30, height=1, command=lambda: self.pokaz_ramke("zmien_haslo_glowne"))
        B4.grid(row=3, column=0, padx=10, pady=5)
        
        B5 = tk.Button(FF_1, text = "Kopie zapasowe (Export/Import)", width = 30, height=1, command=lambda: self.pokaz_ramke("kopie"))
        B5.grid(row=4, column=0, padx=10, pady=5)
        
        B6 = tk.Button(FF_1, text = "Wyloguj", width = 30, height=1, command=lambda:self.close_app())
        B6.grid(row=5, column=0, padx=10, pady=5)
        
    def wczytaj_dane_z_bazy(self, fraza=None):
        #Czyścimy stare dane z tabeli
        for item in self.list_of_pass_k.get_children():
            self.list_of_pass_k.delete(item)
            
        #Pobieramy nowe dane
        rekordy = fun.pobierz_dane_do_tabeli(fraza)
        
        #Wstawiamy do tabeli
        for row in rekordy:
            #row zawiera: (ID, Web_Name, Login, Catalog_Name)
            self.list_of_pass_k.insert("", tk.END, values=row)
            
    def wczytaj_katalogi_z_bazy(self):
        #Czyścimy stare dane z tabeli
        for item in self.list_of_pass.get_children():
            self.list_of_pass.delete(item)
            
        #Pobieramy nowe dane
        rekordy = fun.pobierz_katalogi()
        
        #Wstawiamy do tabeli
        for row in rekordy:
            #row zawiera: (ID, Catalog)
            self.list_of_pass.insert("", tk.END, values=row)
            
    def odswiez_liste_katalogow(self):
        #Pobieramy aktualną listę z bazy
        katalogi_z_bazy = fun.pobierz_liste_katalogow()
        self.combo_cat['values'] = katalogi_z_bazy
            
    def zapisz_klucz_i_odswiez(self):
        sukces = fun.add_key(self.web_name, self.login, self.password, self.combo_cat)
        
        if sukces:
            print("DEBUG: Zapis udany, czyszczę pola...")
            # Czyścimy pola
            self.web_name.delete(0, tk.END)
            self.login.delete(0, tk.END)
            self.password.delete(0, tk.END)
            self.combo_cat.set('')
            
            self.pokaz_ramke("dane_logowania")
            self.wczytaj_dane_z_bazy()
     
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
         
    def zapisz_katalog(self, cat_name, nowy_katalog):
        fun.add_catalog(cat_name)
        nowy_katalog.destroy()
        self.wczytaj_katalogi_z_bazy()
        
    #Funkcja do wyświetlania osobnego okna do dodania nowego katalogu
    def dodaj_katalog_okno(self):
        nowy_katalog = tk.Toplevel()
        nowy_katalog.title("Nowy katalog")
        nowy_katalog.geometry("800x200")
        nowy_katalog.resizable(False, False)
        
        tytul = tk.Label(nowy_katalog, font=("Consolas", 25), text="NOWY KATALOG")
        tytul.grid(row=0, column=0, columnspan=2, padx=10, pady=10)
        
        F1 = ttk.LabelFrame(nowy_katalog, text=" Dodanie nowego katalogu ")
        F1.grid(row=1, column=0, padx=10, pady=10)
        
        cat_name_info = tk.Label(F1, text="Wpisz nazwę nowego katalogu:")
        cat_name_info.grid(row=0, column=0, padx=10, pady=10)
        
        cat_name = tk.Entry(F1, width=30)
        cat_name.grid(row=0, column=1, padx=10, pady=10)
        
        cat_name.bind('<Return>', lambda event: self.zapisz_katalog(cat_name))
        
        save_cat = tk.Button(F1, text="Zapisz", width=10, command=lambda: self.zapisz_katalog(cat_name, nowy_katalog))
        save_cat.grid(row=0, column=2, padx=10, pady=10)
            
    def usun_katalog(self):
        wybrany_katalog = self.list_of_pass.selection()
        
        if not wybrany_katalog:
            messagebox.showwarning("Uwaga", "Wybierz katalog do usunięcia!")
            return

        wartosci = self.list_of_pass.item(wybrany_katalog, "values")
        if not wartosci: return
        
        katalog_id = wartosci[0]
        katalog_nazwa = wartosci[1]
        
        if messagebox.askyesno("Potwierdzenie", f"Czy na pewno usunąć katalog '{katalog_nazwa}'?"):
            if fun.remove_catalog(katalog_id):
                self.wczytaj_katalogi_z_bazy()
    
    #Funkcja, która wyświetla dane konkretnego klucza
    def dane_klucza(self, event):
        klucz = event.widget
        zaznaczony_id = klucz.selection()
        
        if not zaznaczony_id:
            return 
            
        item = klucz.item(zaznaczony_id)
        dane = item['values']
        
        ID = dane[0]
        strona = dane[1]
        katalog = dane[3]
        login = dane[2]
        haslo = fun.decrypt_password(dane[4])
        d_d = dane[5]
        d_m = dane[6]
        
        self.frame_dane_logowania.grid_forget()
        parent = self.frame_dane_logowania.master
        self.frame_klucz = tk.Frame(parent)
        self.frame_klucz.grid(row=0, column=0, sticky='nsew')
        self.frame_klucz.grid_rowconfigure(1, weight=1)
        self.frame_klucz.grid_columnconfigure(0, weight=1)
        
        title = tk.Label(self.frame_klucz, font = ("Consolas", 25), text="KLUCZ")
        title.grid(row=0, column=0, padx=10, pady=(10,20))

        FF_1 = tk.Frame(self.frame_klucz, relief="groove", borderwidth=1)
        FF_1.grid(row=1, column=0, sticky="new", padx=20, pady=10)
        
        #Mechanizm do pokazania i ukrywania hasła
        maska = "********"
        stan_hasla = {"pokazane": False}
        
        tk.Label(FF_1, text=f"STRONA: {strona}", font=("Consolas", 15, "bold")).grid(row=0, column=0, sticky="w", padx=10)
        tk.Label(FF_1, text=f"KATALOG: {katalog}", font=("Consolas", 15, "bold")).grid(row=1, column=0, sticky="w", padx=10)
        tk.Label(FF_1, text=f"LOGIN: {login}", font=("Consolas", 15, "bold")).grid(row=2, column=0, sticky="w", padx=10)
        lbl_haslo_val = tk.Label(FF_1, text=f"Hasło: {maska}", font=("Consolas", 15, "bold"))
        lbl_haslo_val.grid(row=3, column=0, sticky="w", padx=10)
        
        #Funkcja przełączająca
        def przelacz_haslo():
            nonlocal haslo
            if stan_hasla["pokazane"]:
                lbl_haslo_val.config(text=f"Hasło: {maska}")
                B1.config(text="Pokaż hasło")
                stan_hasla["pokazane"] = False
            else:
                lbl_haslo_val.config(text=f"Hasło: {haslo}")
                B1.config(text="Ukryj hasło")
                stan_hasla["pokazane"] = True
                
        frame_haslo = tk.Frame(FF_1)
        frame_haslo.grid(row=4, column=0, sticky="w", padx=10, pady=5) 
        
        B1 = tk.Button(frame_haslo, text="Pokaż hasło", width=15, command=przelacz_haslo)
        btn_copy_pass = tk.Button(frame_haslo, text="Kopiuj", width=15, command=lambda: self.kopiuj_do_schowka(haslo, "Hasło"))
        
        B1.pack(side=tk.LEFT)
        btn_copy_pass.pack(side=tk.LEFT, padx=5)
        
        frame_haslo2 = tk.Frame(FF_1)
        frame_haslo2.grid(row=5, column=0, sticky="w", padx=10, pady=5) 

        def odb_btn():
            nw.config(state='active')
            password.config(state='active')
            iz.config(state='active')
            max_z.config(state='active')
            izs.config(state='active')
            max_zs.config(state='active')
            B3.config(state='active')
            B4.config(state='active')
            
        def zapisz_zmiane():
            new_pass = password.get()
            if not new_pass: return
            
            rezultat = fun.aktualizuj_haslo_wpisu(ID, new_pass)
            
            if isinstance(rezultat, tuple):
                sukces, nowa_data = rezultat
            else:
                sukces, nowa_data = rezultat, "Teraz"

            if sukces:
                messagebox.showinfo("Sukces", "Hasło zostało zmienione.")
                
                nonlocal haslo
                haslo = new_pass
                
                if stan_hasla["pokazane"]:
                    lbl_haslo_val.config(text=f"Hasło: {haslo}")
                
                lbl_data_mod.config(text=f"Data modyfikacji: {nowa_data}")
            
                password.delete(0, tk.END)
                nw.config(state='disabled')
                password.config(state='disabled')
                iz.config(state='disabled')
                max_z.config(state='disabled')
                izs.config(state='disabled')
                max_zs.config(state='disabled')
                B3.config(state='disabled')
                B4.config(state='disabled')
                
        def wroc_do_listy():
            self.frame_klucz.destroy()
            self.frame_dane_logowania.grid(row=0, column=0, sticky='nsew')
            self.wczytaj_dane_z_bazy()
                
        def usun_klucz():
            if messagebox.askyesno("Potwierdzenie", "Czy na pewno usunąć katalog ten klucz?"):
                sukces = fun.remove_key(ID)
                if sukces:
                    print("DEBUG: Usunięto klucz!")
                    self.web_name.delete(0, tk.END)
                    self.login.delete(0, tk.END)
                    self.password.delete(0, tk.END)
                    self.combo_cat.set('')
                    self.pokaz_ramke("dane_logowania")
                    wroc_do_listy()
            
        B2 = tk.Button(frame_haslo2, text="Zmień hasło", width=15, command=odb_btn)
        nw = ttk.Label(frame_haslo2, text="Nowe hasło:", state='disabled')
        password = ttk.Entry(frame_haslo2, width=35, state='disabled')
        iz = ttk.Label(frame_haslo2, text="Ilość znaków:", state='disabled')
        max_z = ttk.Entry(frame_haslo2, width=5, state='disabled')
        izs = ttk.Label(frame_haslo2, text="Ilość znaków specjalnych:", state='disabled')
        max_zs = ttk.Entry(frame_haslo2, width=5, state='disabled')
        B3 = tk.Button(frame_haslo2, text = "Generuj hasło", width = 12, height=1, state='disabled', command=lambda: [fun.generate_key(max_z, max_zs, password), self.aktualizuj_sile(password, lbl_sila_dk)])
        B4 = tk.Button(frame_haslo2, text = "Zapisz", width = 12, height=1, state='disabled', command=zapisz_zmiane)
        
        B2.pack(side=tk.LEFT)
        nw.pack(side=tk.LEFT, padx=5)
        password.pack(side=tk.LEFT, padx=5)
        iz.pack(side=tk.LEFT, padx=5)
        max_z.pack(side=tk.LEFT, padx=5)
        izs.pack(side=tk.LEFT, padx=5)
        max_zs.pack(side=tk.LEFT, padx=5)
        B3.pack(side=tk.LEFT, padx=5)
        B4.pack(side=tk.LEFT, padx=5)
        
        frame_sila_hasla = tk.Frame(FF_1)
        frame_sila_hasla.grid(row=6, column=0, sticky="w", padx=204, pady=5)
        
        lbl_sila_dk = tk.Label(frame_sila_hasla, text="", width=20, font=("Arial", 9, "bold"))
        lbl_sila_dk.pack(side=tk.LEFT, padx=5)

        password.bind('<KeyRelease>', lambda event: self.aktualizuj_sile(password, lbl_sila_dk, event))
        
        tk.Label(FF_1, text=" ", font=("Arial", 8, "bold")).grid(row=7, column=0, sticky="w", padx=10)
        tk.Label(FF_1, text="Historia elementu:", font=("Arial", 8, "bold")).grid(row=8, column=0, sticky="w", padx=10)
        tk.Label(FF_1, text=f"Data dodania: {d_d}", font=("Arial", 8)).grid(row=9, column=0, sticky="w", padx=10)
        tk.Label(FF_1, text=f"Data modyfikacji: {d_m}", font=("Arial", 8)).grid(row=10, column=0, sticky="w", padx=10)
            
        B5 = tk.Button(self.frame_klucz, text = "Usuń klucz", width = 15, height=1, command=usun_klucz)
        B5.grid(row=6, column=0, padx=10, pady=5, sticky='w')
        
        B7 = tk.Button(self.frame_klucz, text = "Test roundtrip", width = 15, height=1, command=lambda: fun.test_encryption_roundtrip(haslo))
        B7.grid(row=7, column=0, padx=10, pady=5, sticky='w')
        
        B8 = tk.Button(self.frame_klucz, text = "Powrót", width = 15, height=1, command=wroc_do_listy)
        B8.grid(row=8, column=0, padx=10, pady=5, sticky='w')


    def dane_logowania_tab(self, parent_container):
        main_frame = tk.Frame(parent_container)
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        title = tk.Label(main_frame, font=("Consolas", 25), text="DANE LOGOWANIA")
        title.grid(row=0, column=0, padx=60, pady=(10,0))
        
        F_1 = ttk.LabelFrame(main_frame, text=" Dane logowania ")
        F_1.grid(row=1, column=0, padx=10, pady=5, sticky='nsew')
        
        F_1.grid_rowconfigure(0, weight=1)
        F_1.grid_columnconfigure(0, weight=1)
        
        FF_1 = ttk.Frame(F_1)
        FF_1.grid(row=0, column=0, padx=10, pady=5, sticky='nsew')
        
        FF_1.grid_rowconfigure(1, weight=1)
        FF_1.grid_columnconfigure(0, weight=1)
        
        filter_frame = ttk.Frame(FF_1)
        filter_frame.grid(row=0, column=0, columnspan=2, sticky='ew', pady=5)
        ttk.Label(filter_frame, text="Strona:").grid(row=0, column=0, padx=5)
        self.filtr_name = ttk.Entry(filter_frame, width=30)
        self.filtr_name.grid(row=0, column=1, padx=5)
        
        btn_szukaj = tk.Button(filter_frame, text="Szukaj", width=10, height=1, command=lambda: self.wczytaj_dane_z_bazy(self.filtr_name.get()))
        btn_szukaj.grid(row=0, column=2, padx=5)
        self.filtr_name.bind('<Return>', lambda event: self.wczytaj_dane_z_bazy(self.filtr_name.get()))
        
        self.list_of_pass_k = ttk.Treeview(FF_1, columns=("ID", "Strona", "Login", "Katalog"), show="headings")
        self.list_of_pass_k.column("ID", width=50, minwidth=30, anchor=tk.CENTER)
        self.list_of_pass_k.column("Strona", width=150, minwidth=150, anchor=tk.W)
        self.list_of_pass_k.column("Login", width=230, minwidth=150, anchor=tk.W)
        self.list_of_pass_k.column("Katalog", width=110, minwidth=80, anchor=tk.W)

        self.list_of_pass_k.heading("ID", text="ID")
        self.list_of_pass_k.heading("Strona", text="Strona")
        self.list_of_pass_k.heading("Login", text="Nazwa użytkownika")
        self.list_of_pass_k.heading("Katalog", text="Katalog")

        scrollbar = ttk.Scrollbar(FF_1, orient="vertical", command=self.list_of_pass_k.yview)
        self.list_of_pass_k.configure(yscrollcommand=scrollbar.set)
        self.list_of_pass_k.grid(row=1, column=0, sticky='nsew')
        scrollbar.grid(row=1, column=1, sticky='ns')
        
        self.list_of_pass_k.bind("<Double-1>", self.dane_klucza)
        self.wczytaj_dane_z_bazy()
        
        return main_frame
        
    def dodaj_dane_logowania_tab(self, parent_container):
        main_frame = tk.Frame(parent_container)
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        title = tk.Label(main_frame, font = ("Consolas", 25), text="DODAJ DANE LOGOWANIA")
        title.grid(row=0, column=0, padx=60, pady=(10,0))
        
        F_1 = ttk.LabelFrame(main_frame, text=" Dodaj dane logowania ")
        F_1.grid(row=1, column=0, padx=10, pady=5, sticky='new')
        
        ttk.Label(F_1, text="Strona:").grid(row=0, column=0, padx=15, sticky='e')
        self.web_name = ttk.Entry(F_1, width=45)
        self.web_name.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(F_1, text="Login/e-mail:").grid(row=1, column=0, padx=15, sticky='e')
        self.login = ttk.Entry(F_1, width=45)
        self.login.grid(row=1, column=1, padx=5, pady=0, sticky='w')
        
        ttk.Label(F_1, text="Hasło:").grid(row=2, column=0, padx=15, sticky='e')
        self.password = ttk.Entry(F_1, width=45)
        self.password.grid(row=2, column=1, padx=5, pady=5, sticky='w')
        
        lbl_sila_ddl = tk.Label(F_1, text="", width=20, font=("Arial", 9, "bold"))
        lbl_sila_ddl.grid(row=2, column=2, padx=5, sticky='w')

        self.password.bind('<KeyRelease>', lambda event: self.aktualizuj_sile(self.password, lbl_sila_ddl, event))
        
        frame_haslo = tk.Frame(F_1)
        frame_haslo.grid(row=3, column=0, columnspan=20, sticky='w', padx=32, pady=5) 
        
        iz = ttk.Label(frame_haslo, text="Ilość znaków:")
        self.max = ttk.Entry(frame_haslo, width=5)
        sz = ttk.Label(frame_haslo, text="Ilość znaków specjalnych:")
        self.spec = ttk.Entry(frame_haslo, width=5)
        B1 = tk.Button(frame_haslo, text = "Generuj hasło", width = 15, height=1, command=lambda: [fun.generate_key(self.max, self.spec, self.password), self.aktualizuj_sile(self.password, lbl_sila_ddl)])
    
        iz.pack(side=tk.LEFT)
        self.max.pack(side=tk.LEFT, padx=5)
        sz.pack(side=tk.LEFT, padx=5)
        self.spec.pack(side=tk.LEFT, padx=5)
        B1.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(F_1, text="Katalog:").grid(row=4, column=0, padx=15, sticky='e')
        self.combo_cat = ttk.Combobox(F_1, width=43, state="readonly")

        katalogi_startowe = fun.pobierz_liste_katalogow()
        self.combo_cat['values'] = katalogi_startowe
        self.combo_cat.grid(row=4, column=1, sticky='w', padx=5, pady=0)
        
        B2 = tk.Button(F_1, text = "Zapisz", width = 15, height=1, command=self.zapisz_klucz_i_odswiez)
        B2.grid(row=5, column=1, padx=5, pady=5, sticky='w')
        
        return main_frame
    
    def katalogi_tab(self, parent_container):
        main_frame = tk.Frame(parent_container)
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        title = tk.Label(main_frame, font = ("Consolas", 25), text="KATALOGI")
        title.grid(row=0, column=0, padx=60, pady=(10,0))
        
        F_1 = ttk.LabelFrame(main_frame, text=" Katalogi ")
        F_1.grid(row=1, column=0, padx=10, pady=5, sticky='nsew')
        
        F_1.grid_rowconfigure(0, weight=1)
        F_1.grid_columnconfigure(0, weight=1)
        
        FF_1 = ttk.Frame(F_1)
        FF_1.grid(row=0, column=0, padx=10, pady=5, sticky='nsew')
        
        FF_1.grid_rowconfigure(1, weight=1)
        FF_1.grid_columnconfigure(0, weight=1)
        
        self.list_of_pass = ttk.Treeview(FF_1, columns=("ID", "Katalog"), show="headings")
        self.list_of_pass.column("ID", width=100, minwidth=50, anchor=tk.CENTER)
        self.list_of_pass.column("Katalog", width=150, minwidth=80, anchor=tk.CENTER)

        self.list_of_pass.heading("ID", text="ID")
        self.list_of_pass.heading("Katalog", text="Katalog")
        
        scrollbar = ttk.Scrollbar(FF_1, orient="vertical", command=self.list_of_pass.yview)
        self.list_of_pass.configure(yscrollcommand=scrollbar.set)

        self.list_of_pass.grid(row=1, column=0, sticky='nsew')
        scrollbar.grid(row=1, column=1, sticky='ns')
        
        B1 = tk.Button(FF_1, text = "Dodaj katalog", width = 20, height=1, command=self.dodaj_katalog_okno)
        B1.grid(row=1, column=2, padx=10, pady=10, sticky='n')
        
        B2 = tk.Button(FF_1, text = "Usuń katalog", width = 20, height=1, command=self.usun_katalog)
        B2.grid(row=1, column=2, padx=10, pady=50, sticky='n')
        
        self.wczytaj_katalogi_z_bazy()
        
        return main_frame
    
    def zmien_haslo_glowne_tab(self, parent_container):
        
        def toggle_password(op, np, np2, B1):
            if op and np and np2.cget('show') == '*':
                op.config(show='')
                np.config(show='')
                np2.config(show='')
                B1.config(text='Ukryj hasło')
            else:
                op.config(show='*')
                np.config(show='*')
                np2.config(show='*')
                B1.config(text='Pokaż hasło')
                
        main_frame = tk.Frame(parent_container)
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        title = tk.Label(main_frame, font = ("Consolas", 25), text="ZMIANA HASŁA GŁÓWNEGO")
        title.grid(row=0, column=0, padx=60, pady=(10,0))
        
        F_1 = ttk.LabelFrame(main_frame, text=" Zmiana hasła ")
        F_1.grid(row=1, column=0, padx=10, pady=5, sticky='nsew')
        
        ttk.Label(F_1, text="Stare hasło:").grid(row=0, column=0, padx=5, sticky='e')
        self.old_pass = ttk.Entry(F_1, width=60, show="*")
        self.old_pass.grid(row=0, column=1, padx=5, pady=20, sticky='ew')
        
        ttk.Label(F_1, text="Nowe hasło:").grid(row=1, column=0, padx=5, sticky='e')
        self.new_pass = ttk.Entry(F_1, width=60, show="*")
        self.new_pass.grid(row=1, column=1, padx=5, pady=5)
        
        lbl_sila_zhg = tk.Label(F_1, text="", width=20, font=("Arial", 9, "bold"))
        lbl_sila_zhg.grid(row=1, column=2, padx=5, pady=5)
        
        self.new_pass.bind('<KeyRelease>', lambda event: self.aktualizuj_sile(self.new_pass, lbl_sila_zhg, event))
        
        ttk.Label(F_1, text="Potwierdź nowe hasło:").grid(row=2, column=0, padx=5, sticky='e')
        self.new_pass_2 = ttk.Entry(F_1, width=60, show="*")
        self.new_pass_2.grid(row=2, column=1, padx=5)
        
        B1 = tk.Button(F_1, text = "Pokaż hasło", width = 10, height=1, command=lambda: toggle_password(self.old_pass, self.new_pass, self.new_pass_2, B1))
        B1.grid(row=3, column=1, padx=5, pady=10, sticky='w')
        
        B2 = tk.Button(F_1, text = "Zmień hasło", width = 20, height=1, command=lambda:fun._change_master_password(self.old_pass, self.new_pass, self.new_pass_2))
        B2.grid(row=3, column=1, padx=5, pady=10, sticky='e')
        
        return main_frame
    
    def kopie_zapasowe_tab(self, parent_container):
        main_frame = tk.Frame(parent_container)
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        title = tk.Label(main_frame, font=("Consolas", 25), text="KOPIE ZAPASOWE")
        title.grid(row=0, column=0, padx=60, pady=(10,0))
        
        F_Main = ttk.LabelFrame(main_frame, text=" Import / Eksport Danych ")
        F_Main.grid(row=1, column=0, padx=10, pady=5, sticky='nsew')
        F_Main.grid_rowconfigure(0, weight=1)
        F_Main.grid_columnconfigure(0, weight=1)
        
        FF_Content = ttk.Frame(F_Main)
        FF_Content.grid(row=0, column=0, padx=20, pady=20, sticky='nsew')

        lbl_export = tk.Label(FF_Content, text="Eksport danych (Backup)", font=("Arial", 14, "bold"))
        lbl_export.grid(row=0, column=0, sticky="w", pady=(0, 10))
        
        btn_exp_csv = tk.Button(FF_Content, text="Eksport do CSV (Niezaszyfrowany)", width=40, bg="#ffcccc",
                                command=self.handle_export_csv)
        btn_exp_csv.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        tk.Label(FF_Content, text="Uwaga: Plik będzie czytelny dla każdego!", fg="red", font=("Arial", 8)).grid(row=2, column=0, sticky="w", padx=15)
        
        btn_exp_enc = tk.Button(FF_Content, text="Eksport zaszyfrowany (Bezpieczny)", width=40, bg="#ccffcc",
                                command=self.handle_export_encrypted)
        btn_exp_enc.grid(row=3, column=0, padx=10, pady=(15, 5), sticky="w")
        tk.Label(FF_Content, text="Wymaga podania hasła do zabezpieczenia pliku.", font=("Arial", 8)).grid(row=4, column=0, sticky="w", padx=15)

        ttk.Separator(FF_Content, orient='horizontal').grid(row=5, column=0, sticky="ew", pady=30)

        lbl_import = tk.Label(FF_Content, text="Import danych", font=("Arial", 14, "bold"))
        lbl_import.grid(row=6, column=0, sticky="w", pady=(0, 10))
        
        btn_imp_csv = tk.Button(FF_Content, text="Importuj z CSV", width=40, command=self.handle_import_csv)
        btn_imp_csv.grid(row=7, column=0, padx=10, pady=5, sticky="w")
        
        btn_imp_enc = tk.Button(FF_Content, text="Importuj zaszyfrowany plik", width=40, command=self.handle_import_encrypted)
        btn_imp_enc.grid(row=8, column=0, padx=10, pady=5, sticky="w")
        
        return main_frame

    def handle_export_csv(self):
        if not messagebox.askyesno("Ostrzeżenie bezpieczeństwa", 
                                   "Eksport do CSV zapisze hasła jawnym tekstem.\n"
                                   "Każdy, kto uzyska dostęp do tego pliku, pozna Twoje hasła.\n\n"
                                   "Czy na pewno chcesz kontynuować?"):
            return

        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("Pliki CSV", "*.csv"), ("Wszystkie pliki", "*.*")])
        if filename:
            fun.export_csv(filename)

    def handle_import_csv(self):
        filename = filedialog.askopenfilename(filetypes=[("Pliki CSV", "*.csv"), ("Wszystkie pliki", "*.*")])
        if filename:
            count = fun.import_csv(filename)
            if count > 0:
                messagebox.showinfo("Import zakończony", f"Zaimportowano {count} wpisów.")
                self.wczytaj_dane_z_bazy()
                self.wczytaj_katalogi_z_bazy()
            else:
                messagebox.showwarning("Import", "Nie zaimportowano żadnych wpisów (lub wystąpił błąd).")

    def handle_export_encrypted(self):
        filename = filedialog.asksaveasfilename(defaultextension=".dat", filetypes=[("Pliki zaszyfrowane", "*.dat"), ("Pliki JSON", "*.json")])
        if not filename:
            return
            
        pwd = simpledialog.askstring("Hasło backupu", "Podaj hasło, którym zaszyfrować plik backupu:\n(Nie musi to być hasło główne)", show='*')
        if pwd:
            fun.export_encrypted(filename, pwd)

    def handle_import_encrypted(self):
        filename = filedialog.askopenfilename(filetypes=[("Pliki zaszyfrowane", "*.dat"), ("Pliki JSON", "*.json")])
        if not filename:
            return
            
        pwd = simpledialog.askstring("Hasło backupu", "Podaj hasło do odszyfrowania pliku:", show='*')
        if pwd:
            count = fun.import_encrypted(filename, pwd)
            if count > 0:
                messagebox.showinfo("Import zakończony", f"Zaimportowano {count} wpisów.")
                self.wczytaj_dane_z_bazy()
                self.wczytaj_katalogi_z_bazy()

      
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

if __name__ == "__main__":
    app = App()
    app.mainloop()
