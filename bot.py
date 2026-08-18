"""Bot anti-phishing de Discord.

Flujo: el usuario sube una captura -> OCR + lectura de QR -> extracción de
URLs -> análisis (heurísticas + threat intel) -> embed con el veredicto.

El bot NO interactúa de forma abusiva con los sitios: solo sigue
redirecciones con HEAD para revelar el destino de los acortadores.
"""
from __future__ import annotations

import logging

import discord
from discord import app_commands

import config
from analysis.scanner import scan_message
from bot_ui import help_embed, member_welcome_embed, message_embed, no_url_embed
from extractors.ocr import extract_urls_from_image, find_urls_in_text
from extractors.qr import extract_qr_urls

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("antiphishing")

_IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif")

intents = discord.Intents.default()
intents.message_content = True  # necesario para leer adjuntos/comandos
intents.members = True  # necesario para saludar a nuevos miembros (privilegiado)
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)


def _is_image(attachment: discord.Attachment) -> bool:
    if attachment.content_type and attachment.content_type.startswith("image/"):
        return True
    return attachment.filename.lower().endswith(_IMAGE_EXTS)


async def process_image(message: discord.Message, data: bytes) -> None:
    """Extrae URLs de una imagen y responde con el análisis."""
    # 1) Extracción: QR + OCR de texto.
    qr_urls = extract_qr_urls(data)
    ocr_urls, ocr_text = extract_urls_from_image(data)

    all_urls = list(dict.fromkeys(qr_urls + ocr_urls))  # únicas, en orden

    # 2) Análisis del mensaje completo (URLs + remitente + texto).
    report = scan_message(all_urls, ocr_text)
    log.info(
        "IMAGEN | urls=%s phones=%s scam=%s -> %s (score %d)",
        all_urls,
        [p.e164 for p in report.phones],
        bool(report.scam_signal),
        report.risk,
        report.score,
    )

    # 3) Respuesta: un único embed con el veredicto agregado.
    if not all_urls and not report.phones and not report.scam_signal:
        await message.reply(embed=no_url_embed(ocr_text, report), mention_author=False)
        return
    await message.reply(embed=message_embed(report), mention_author=False)


@tree.command(name="ayuda", description="Muestra la guía de uso del bot anti-phishing")
async def ayuda(interaction: discord.Interaction) -> None:
    # ephemeral=True: la guía solo la ve quien la pidió (no llena el canal).
    await interaction.response.send_message(embed=help_embed(), ephemeral=True)


@tree.command(name="analizar", description="Analiza una URL o mensaje sospechoso de phishing")
@app_commands.describe(texto="Pega aquí la URL o el texto del mensaje sospechoso")
async def analizar(interaction: discord.Interaction, texto: str) -> None:
    # El análisis hace peticiones de red (expandir acortadores), que pueden
    # tardar >3s; 'defer' evita que Discord marque el comando como caído.
    await interaction.response.defer(thinking=True)
    urls = find_urls_in_text(texto)
    report = scan_message(urls, texto)
    log.info(
        "/analizar %r | urls=%s phones=%s scam=%s -> %s (score %d)",
        texto[:150],
        urls,
        [p.e164 for p in report.phones],
        bool(report.scam_signal),
        report.risk,
        report.score,
    )

    if not urls and not report.phones and not report.scam_signal:
        await interaction.followup.send(
            "No encontré URLs ni números en el texto. Pega el enlace o el mensaje completo."
        )
        return
    await interaction.followup.send(embed=message_embed(report))


@client.event
async def on_ready() -> None:
    log.info("Conectado como %s (id=%s)", client.user, client.user.id)
    # Sincroniza los comandos slash. Si hay GUILD_ID, se registran al instante
    # en ese servidor; sin él, el registro global puede tardar hasta ~1 hora.
    try:
        if config.GUILD_ID:
            guild = discord.Object(id=config.GUILD_ID)
            tree.copy_global_to(guild=guild)
            synced = await tree.sync(guild=guild)
        else:
            synced = await tree.sync()
        log.info("Comandos slash sincronizados: %d", len(synced))
    except Exception:
        log.exception("No se pudieron sincronizar los comandos slash")


@client.event
async def on_guild_join(guild: discord.Guild) -> None:
    """Al entrar a un servidor nuevo, publica el manual de bienvenida."""
    # Canal de sistema si existe; si no, el primer canal donde pueda escribir.
    channel = guild.system_channel
    if channel is None or not channel.permissions_for(guild.me).send_messages:
        channel = next(
            (c for c in guild.text_channels if c.permissions_for(guild.me).send_messages),
            None,
        )
    if channel is not None:
        try:
            await channel.send(embed=help_embed())
        except discord.DiscordException:
            log.exception("No pude enviar el mensaje de bienvenida en %s", guild.name)


@client.event
async def on_member_join(member: discord.Member) -> None:
    """Saluda a cada persona que se une al servidor."""
    if member.bot:
        return
    guild = member.guild
    channel = guild.system_channel
    if channel is None or not channel.permissions_for(guild.me).send_messages:
        channel = next(
            (c for c in guild.text_channels if c.permissions_for(guild.me).send_messages),
            None,
        )
    if channel is not None:
        try:
            await channel.send(content=member.mention, embed=member_welcome_embed())
        except discord.DiscordException:
            log.exception("No pude saludar a %s en %s", member, guild.name)


@client.event
async def on_message(message: discord.Message) -> None:
    if message.author.bot:
        return

    images = [a for a in message.attachments if _is_image(a)]
    if not images:
        return

    async with message.channel.typing():
        for attachment in images:
            try:
                data = await attachment.read()
                await process_image(message, data)
            except Exception:
                log.exception("Error procesando la imagen %s", attachment.filename)
                await message.reply(
                    "⚠️ Ocurrió un error al procesar la imagen.",
                    mention_author=False,
                )


def main() -> None:
    config.validate()
    client.run(config.DISCORD_TOKEN)


if __name__ == "__main__":
    main()
