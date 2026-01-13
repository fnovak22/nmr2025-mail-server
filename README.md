# nmr2025-mail-server
Repozitorij za timski projektni zadatak za kolegij Napredne Mreže Računala.

# Setup

Potrebno je instalirati Python. U razvoju projekta se koristila python verzija `3.10.10`.

Potrebno je instalirati Tkinter za python (to je biblioteka za GUI):
```
sudo apt install python3-tk
```

Instaliranje dependencyja (preporuča se u virtual environment):
```
python -m pip install -r requirements.txt
```

# Pokretanje

**Windows**

Pomoću `server.bat` i `client.bat`.

**Linux**

Server: `python Server\server.py`

Klijent: `python Client\client.py`