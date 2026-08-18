"""Análisis del número remitente (extracción + validación con libphonenumber).

Las notificaciones oficiales (multas, bancos, aduanas) casi nunca llegan desde
un número VOIP o de red fija: usan códigos cortos o remitentes con nombre. Por
eso el tipo de línea es una señal útil para detectar smishing.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import phonenumbers
from phonenumbers import PhoneNumberType, carrier, geocoder, number_type

# Región por defecto para números escritos en formato local (sin '+').
DEFAULT_REGION = "CL"

_TYPE_NAMES = {
    PhoneNumberType.MOBILE: "móvil",
    PhoneNumberType.FIXED_LINE: "red fija",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fija o móvil",
    PhoneNumberType.VOIP: "VOIP",
    PhoneNumberType.PREMIUM_RATE: "tarifa premium",
    PhoneNumberType.TOLL_FREE: "gratuito",
    PhoneNumberType.SHARED_COST: "coste compartido",
    PhoneNumberType.PERSONAL_NUMBER: "personal",
    PhoneNumberType.PAGER: "buscapersonas",
    PhoneNumberType.UAN: "UAN",
    PhoneNumberType.VOICEMAIL: "buzón de voz",
    PhoneNumberType.UNKNOWN: "desconocido",
}

# Tipos de línea que no corresponden a un remitente institucional legítimo.
_SUSPICIOUS_TYPES = {
    PhoneNumberType.VOIP: 3,
    PhoneNumberType.PREMIUM_RATE: 3,
    PhoneNumberType.FIXED_LINE: 2,
    PhoneNumberType.FIXED_LINE_OR_MOBILE: 1,
    PhoneNumberType.PERSONAL_NUMBER: 2,
}


@dataclass
class PhoneInfo:
    raw: str
    e164: str
    valid: bool
    region: str | None
    zone: str
    carrier: str
    line_type: str
    signals: list[str] = field(default_factory=list)
    score: int = 0


def _analyze_one(num: phonenumbers.PhoneNumber, raw: str) -> PhoneInfo:
    ntype = number_type(num)
    info = PhoneInfo(
        raw=raw,
        e164=phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164),
        valid=phonenumbers.is_valid_number(num),
        region=geocoder.region_code_for_number(num),
        zone=geocoder.description_for_number(num, "es") or "desconocida",
        carrier=carrier.name_for_number(num, "es") or "desconocido",
        line_type=_TYPE_NAMES.get(ntype, "desconocido"),
    )

    if not info.valid:
        info.signals.append("El número no es válido según el plan de numeración.")
        info.score += 2

    weight = _SUSPICIOUS_TYPES.get(ntype)
    if weight:
        info.signals.append(
            f"El SMS proviene de una línea de tipo '{info.line_type}'; "
            "las entidades oficiales no notifican multas ni pagos desde este tipo de número."
        )
        info.score += weight

    return info


def analyze_phones(text: str, region: str = DEFAULT_REGION) -> list[PhoneInfo]:
    """Extrae y analiza todos los números de teléfono presentes en el texto."""
    results: list[PhoneInfo] = []
    seen: set[str] = set()
    for match in phonenumbers.PhoneNumberMatcher(text, region):
        info = _analyze_one(match.number, match.raw_string)
        if info.e164 not in seen:
            seen.add(info.e164)
            results.append(info)
    return results
