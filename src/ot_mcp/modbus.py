"""Stałe protokołu Modbus używane w całym projekcie."""

# Kody funkcji, które modyfikują stan sterownika (zapisy). Reszta to odczyty lub diagnostyka.
WRITE_FUNCTION_CODES = frozenset({5, 6, 15, 16, 22, 23})

# Nazwy kodów funkcji; przydają się w odpowiedziach, bo Claude lepiej czyta "Write Single
# Register (6)" niż samo "6".
FUNCTION_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    8: "Diagnostics",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    43: "Encapsulated Interface Transport (Read Device Identification)",
}


def function_name(code: int) -> str:
    """Zwraca czytelną nazwę kodu funkcji albo ogólny opis dla nieznanego kodu."""
    return FUNCTION_NAMES.get(code, f"Unknown/Vendor-specific function {code}")
