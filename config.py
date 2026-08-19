"""Carga y expone la configuración desde variables de entorno (.env)."""
import os

from dotenv import load_dotenv

load_dotenv()


def _get_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


# --- Discord ---
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
# ID del servidor para registrar los comandos slash al instante (0 = global).
GUILD_ID = _get_int("GUILD_ID", 0)
# Enlace de donación ("invítame un café"). Por defecto, el mismo de la web.
DONATION_URL = os.getenv("DONATION_URL", "https://mpago.la/1UyNrnp").strip()

# --- Threat intel (opcionales) ---
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()

# --- Comportamiento ---
EXPAND_SHORTENERS = _get_bool("EXPAND_SHORTENERS", True)
MAX_REDIRECTS = _get_int("MAX_REDIRECTS", 5)
REQUEST_TIMEOUT = _get_int("REQUEST_TIMEOUT", 8)

# User-Agent neutro para las peticiones de red (solo lectura de cabeceras)
HTTP_USER_AGENT = (
    "Mozilla/5.0 (compatible; AntiPhishingBot/1.0; +defensivo, solo-lectura)"
)


def validate() -> None:
    """Lanza un error claro si falta configuración imprescindible."""
    if not DISCORD_TOKEN:
        raise RuntimeError(
            "Falta DISCORD_TOKEN. Copia .env.example a .env y pega tu token."
        )
