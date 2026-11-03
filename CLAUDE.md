# CLAUDE.md — zasady projektu OT MCP

Serwer MCP udostępniający Claude'owi **wyłącznie syntetyczne** dane z fikcyjnego laboratorium OT
(urządzenia, zdarzenia Modbus, detekcja anomalii, mapowanie na MITRE ATT&CK for ICS).
Projekt portfolio na GitHubie. Autor jest specjalistą cyberbezpieczeństwa IT/OT, ale początkującym
programistą — tłumacz po polsku, co robisz i dlaczego.

## Zasady nienegocjowalne
1. **Tylko dane syntetyczne.** Żadnych danych z pracy, prawdziwych adresów IP/hostów, nazw firm
   klientów, numerów seryjnych ani konfiguracji realnych systemów. Adresy tylko z zakresów prywatnych
   (RFC 1918) lub dokumentacyjnych. Producenci i modele są fikcyjne.
2. **Narzędzia tylko do odczytu.** Serwer nie łączy się z siecią, nie wysyła pakietów, nie zapisuje
   plików i nie wykonuje poleceń. Żadnego skanowania ani Modbusa „naprawdę".
3. **Brak ścieżek od użytkownika.** Ścieżki do danych są stałe w kodzie; parametry narzędzi to tylko
   proste typy z walidacją zakresów (`hours`, `limit`, filtry).
4. **Dane są niezaufane dla modelu.** Pola tekstowe z JSON trafiają do kontekstu Claude'a, więc
   w danych nie umieszczamy niczego w rodzaju instrukcji (ryzyko prompt injection).
5. **Wersje narzędzi z zewnątrz weryfikujemy.** Identyfikatory technik MITRE sprawdzamy na
   attack.mitre.org, a nie z pamięci.

## Stos i konwencje
- Python ≥ 3.10 (lokalnie 3.11), menedżer pakietów **uv**: `uv run pytest`, `uv run ruff check .`.
- SDK: `mcp` 2.x. Klasa serwera to `MCPServer` (następca FastMCP z 1.x).
- Kod i identyfikatory po angielsku, **komentarze po polsku**, docstringi narzędzi po angielsku
  (czyta je Claude).
- Modele danych w Pydantic (`src/ot_mcp/models.py`); reguły detekcji to małe, czyste funkcje
  w `src/ot_mcp/detection/rules.py`.
- „Teraz" to **czas odniesienia zapisany w danych**, nie `datetime.now()` (deterministyczne testy).
- Dane generuje `scripts/generate_data.py` ze stałym seedem; wygenerowane JSON-y są w repo.

## Testy
- TDD: najpierw test, potem kod. Każda reguła detekcji ma test pozytywny i negatywny.
- Test całego scenariusza: wszystkie fazy ataku wykryte, zero fałszywych alarmów na ruchu bazowym.
- Przed zakończeniem kroku: `uv run pytest` i `uv run ruff check .` muszą przechodzić.

## Pułapki, na które już trafiliśmy
- W narzędziach MCP błędy dla użytkownika zgłaszaj jako `ToolError` (zob. `_guard` w `server.py`).
  Zwykły `ValueError` model widzi tylko jako „Error executing tool", bez treści.
- Projekt wspiera Pythona ≥ 3.10: bez składni z 3.12 (np. `def f[T]()`).
- `.mcp.json` ze ścieżkami z tego komputera jest w `.gitignore`; wzór to `.mcp.json.example`.
- W PowerShellu treść commita przekazuj plikiem (`git commit -F`), bo here-string przez stdin nie działa.
- Serwer MCP z `.mcp.json` ładuje się dopiero przy starcie nowej sesji.

## Git
- Commit po każdym ukończonym kroku planu. **Nie pushuj** na GitHuba bez wyraźnej zgody autora.
- Repozytorium na GitHubie ma być **prywatne**.
- Nie dodawaj do repo plików `.env`, kluczy ani niczego spoza zakresu projektu.
