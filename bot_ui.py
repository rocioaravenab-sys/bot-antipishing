"""Construcción de los embeds/mensajes que el bot envía a Discord."""
from __future__ import annotations

import discord

from analysis.scanner import (
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    MessageReport,
)

_COLORS = {
    RISK_HIGH: 0xE02424,    # rojo
    RISK_MEDIUM: 0xF59E0B,  # ámbar
    RISK_LOW: 0x16A34A,     # verde
}
_EMOJI = {RISK_HIGH: "🔴", RISK_MEDIUM: "🟠", RISK_LOW: "🟢"}
_TITLE = {
    RISK_HIGH: "PHISHING PROBABLE — NO ABRIR",
    RISK_MEDIUM: "Sospechoso — proceder con cautela",
    RISK_LOW: "Sin señales claras de phishing",
}


def message_embed(report: MessageReport) -> discord.Embed:
    """Embed único con el veredicto agregado del mensaje (URL + remitente)."""
    risk = report.risk
    embed = discord.Embed(
        title=f"{_EMOJI[risk]} {_TITLE[risk]}",
        color=_COLORS[risk],
    )

    # --- Remitente (número de teléfono) ---
    for ph in report.phones:
        valido = "válido" if ph.valid else "no válido"
        embed.add_field(
            name="📞 Remitente",
            value=(
                f"`{ph.e164}` · {valido}\n"
                f"Zona: {ph.zone} · Tipo: **{ph.line_type}** · Operador: {ph.carrier}"
            ),
            inline=False,
        )

    # --- URLs (sin hacerlas clicables) ---
    for r in report.urls:
        val = f"`{r.url}`"
        if r.final_url != r.url:
            val += f"\n→ destino: `{r.final_url}`"
        embed.add_field(name="🔗 Enlace", value=val, inline=False)

    # --- Señales agregadas ---
    signals: list[str] = []
    if report.scam_signal:
        signals.append(report.scam_signal)
    for ph in report.phones:
        signals.extend(ph.signals)
    for r in report.urls:
        signals.extend(r.signals)

    if signals:
        bullets = "\n".join(f"• {s}" for s in signals[:14])
        embed.add_field(name="Señales", value=bullets, inline=False)
    else:
        embed.add_field(
            name="Señales",
            value="No se encontraron indicadores automáticos. Verifica igualmente.",
            inline=False,
        )

    embed.add_field(
        name="Nivel de riesgo",
        value=f"**{risk}** (score: {report.score})",
        inline=True,
    )
    embed.set_footer(
        text="Bot anti-phishing · No compartas datos ni contraseñas en enlaces sospechosos."
    )
    return embed


def help_embed() -> discord.Embed:
    """Manual de bienvenida / guía rápida de uso del bot."""
    embed = discord.Embed(
        title="🛡️ AntiPhishingBot — Guía rápida",
        description=(
            "Analizo capturas y enlaces para detectar **phishing y estafas** "
            "(SMS, correos, WhatsApp). Aviso del riesgo; no ataco ni abro nada."
        ),
        color=0x2563EB,
    )
    embed.add_field(
        name="📷 Sube una captura",
        value=(
            "Arrastra una imagen del mensaje sospechoso a un canal y la analizo "
            "automáticamente (leo el texto por OCR y los códigos QR)."
        ),
        inline=False,
    )
    embed.add_field(
        name="🔗 /analizar <texto>",
        value="Pega una URL o el texto de un mensaje y te digo si es peligroso.",
        inline=False,
    )
    embed.add_field(
        name="❓ /ayuda",
        value="Muestra esta guía cuando la necesites.",
        inline=False,
    )
    embed.add_field(
        name="🔎 Qué reviso",
        value=(
            "• Destino real de enlaces acortados (bit.ly…)\n"
            "• Dominios sospechosos, aleatorios o suplantadores\n"
            "• Número remitente (VOIP/línea no institucional)\n"
            "• Lenguaje de estafa (multas, premios, bonos, urgencia)"
        ),
        inline=False,
    )
    embed.add_field(
        name="🚦 Cómo leer el resultado",
        value="🟢 Bajo · 🟠 Sospechoso · 🔴 Phishing probable",
        inline=False,
    )
    embed.set_footer(
        text="Regla de oro: nunca ingreses datos ni contraseñas en enlaces que no esperabas."
    )
    return embed


def member_welcome_embed() -> discord.Embed:
    """Saludo a cada persona que se une al servidor."""
    embed = discord.Embed(
        title="👋 ¡Te damos la bienvenida!",
        description=(
            "Copia y pega aquí una imagen de ese **SMS sospechoso** que te llegó "
            "y verifico si es una estafa. Y si lo es, **podemos reportarlo**. 🛡️"
        ),
        color=0x2563EB,
    )
    embed.add_field(
        name="¿Cómo empiezo?",
        value=(
            "• Sube la captura del mensaje a este canal.\n"
            "• O usa `/analizar` con el enlace sospechoso.\n"
            "• Escribe `/ayuda` para ver la guía completa."
        ),
        inline=False,
    )
    return embed


def no_url_embed(ocr_text: str, report: MessageReport | None = None) -> discord.Embed:
    """Cuando no hay URL: aún así informamos del remitente/lenguaje sospechoso."""
    # Si hay señales de remitente o estafa, mostramos el veredicto igualmente.
    if report and (report.phones or report.scam_signal):
        return message_embed(report)

    embed = discord.Embed(
        title="🔎 No encontré ninguna URL en la imagen",
        description=(
            "No detecté enlaces por OCR ni códigos QR. "
            "Asegúrate de que la captura muestre el enlace completo y con buena calidad."
        ),
        color=0x6B7280,
    )
    if ocr_text.strip():
        snippet = ocr_text.strip()[:500]
        embed.add_field(name="Texto reconocido", value=f"```{snippet}```", inline=False)
    return embed
