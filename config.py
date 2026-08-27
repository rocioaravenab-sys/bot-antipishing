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

# --- API REST (para la app móvil) ---
# Si se define, /analyze y /analyze-text exigen el header X-API-Key.
API_KEY = os.getenv("API_KEY", "").strip()

# Rate limiting (token bucket in-process, por X-Install-Id o IP).
RATE_LIMIT = _get_bool("RATE_LIMIT", True)
RL_ANALYZE_PER_MIN = _get_int("RL_ANALYZE_PER_MIN", 20)
RL_TEXT_PER_MIN = _get_int("RL_TEXT_PER_MIN", 60)
RL_RULES_PER_HOUR = _get_int("RL_RULES_PER_HOUR", 30)

# --- Threat intel (opcionales) ---
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()

# --- Intel de dominio: antigüedad (RDAP) + certificado TLS ---
# Sin claves. Se puede apagar si añade demasiada latencia.
DOMAIN_INTEL = _get_bool("DOMAIN_INTEL", True)
RDAP_BASE = os.getenv("RDAP_BASE", "https://rdap.org").strip()

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
