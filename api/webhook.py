import os
import json
import asyncio

from telegram import Update
from telegram.ext import Application, MessageHandler, ContextTypes, filters

from analyzer import SiteAnalyzer

# Vercel: set env var TG_BOT_TOKEN in Project Settings
BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
PROXY = os.getenv("TG_PROXY") or None


def _build_app() -> Application:
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(MessageHandler(filters.ALL, _handle_message))
    return app


def _extract_urls_from_text(text: str) -> list[str]:
    import re

    url_re = re.compile(r"https?://[^\s<>\"]+", re.I)
    urls = set()
    for u in url_re.findall(text or ""):
        urls.add(u.strip().rstrip(").,;!\"'"))
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or " " in line:
            continue
        if "." in line and not line.startswith("#") and not line.startswith("http"):
            urls.add(line)
    out = []
    for u in urls:
        u = u.strip()
        if not u:
            continue
        if not u.startswith(("http://", "https://")):
            u = "https://" + u
        out.append(u)
    return sorted(set(out))


def _extract_urls_from_file_bytes(data: bytes) -> list[str]:
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        text = data.decode("latin-1", errors="ignore")
    return _extract_urls_from_text(text)


def _is_detected_gateway(r: dict) -> bool:
    return r.get("gateway") not in ("None Detected", "Generic / Private Gate 💳")


def _format_result(url: str, r: dict) -> str:
    gw = r.get("gateway", "None Detected")
    status = r.get("status", "Success")
    chk = r.get("checkout_link", "Not Found")
    sec = r.get("security", "None Detected")
    cap = r.get("captcha", "None Detected")
    return (
        f"🔗 {url}\n"
        f"💳 Gateway: {gw}\n"
        f"🛒 Checkout: {chk}\n"
        f"🛡️ Security: {sec}\n"
        f"🤖 Captcha: {cap}\n"
        f"🛰️ Status: {status}\n"
    )


async def _scan_urls(urls: list[str], analyzer: SiteAnalyzer, max_concurrent: int = 20):
    sem = asyncio.Semaphore(max_concurrent)
    results: list[tuple[str, dict]] = []

    async def one(u: str):
        async with sem:
            try:
                r = await analyzer.analyze_site(u, proxy=PROXY)
            except Exception as e:
                r = {"status": f"Error: {e}", "gateway": "None Detected"}
            results.append((u, r))

    await asyncio.gather(*(one(u) for u in urls), return_exceptions=True)
    return results


async def _reply_in_chunks(update: Update, text: str):
    if not update.message:
        return
    limit = 3500
    if len(text) <= limit:
        await update.message.reply_text(text, disable_web_page_preview=True)
        return
    parts: list[str] = []
    current = ""
    for block in text.split("\n\n"):
        if len(current) + len(block) + 2 > limit and current:
            parts.append(current)
            current = block
        else:
            current = block if not current else current + "\n\n" + block
    if current:
        parts.append(current)
    for p in parts:
        await update.message.reply_text(p, disable_web_page_preview=True)


async def _handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return

    analyzer = SiteAnalyzer()

    doc = update.message.document
    if doc:
        try:
            f = await context.bot.get_file(doc.file_id)
            data = await f.download_as_bytearray()
            urls = _extract_urls_from_file_bytes(bytes(data))
        except Exception:
            urls = []

        if not urls:
            await update.message.reply_text("No URLs found in file.")
            return

        # Vercel/serverless safety: cap file size to avoid timeouts
        urls = urls[:200]
        await update.message.reply_text(f"Found {len(urls)} sites. Scanning...")
        scans = await _scan_urls(urls, analyzer, max_concurrent=20)
        detected = [(u, r) for (u, r) in scans if _is_detected_gateway(r)]
        if not detected:
            await update.message.reply_text("No gateways detected in this file.")
            return

        msg = "\n\n".join(_format_result(u, r) for u, r in detected)
        await _reply_in_chunks(update, msg)
        return

    text = update.message.text or update.message.caption or ""
    urls = _extract_urls_from_text(text)
    if not urls:
        await update.message.reply_text("Send a website URL, or upload a .txt file with one site per line.")
        return

    scans = await _scan_urls(urls[:50], analyzer, max_concurrent=20)
    detected = [(u, r) for (u, r) in scans if _is_detected_gateway(r)]
    if not detected:
        await update.message.reply_text("No gateway detected (or only generic payment keywords).")
        return

    msg = "\n\n".join(_format_result(u, r) for u, r in detected[:10])
    await update.message.reply_text(msg, disable_web_page_preview=True)


def handler(request):
    """
    Vercel Python function entrypoint.
    Telegram webhook should POST updates to /api/webhook
    """
    if not BOT_TOKEN:
        return {
            "statusCode": 500,
            "headers": {"content-type": "text/plain"},
            "body": "Missing TG_BOT_TOKEN env var.",
        }

    try:
        body = request.get("body") if isinstance(request, dict) else getattr(request, "body", None)
        if isinstance(body, (bytes, bytearray)):
            body = body.decode("utf-8", errors="ignore")
        if not body:
            return {"statusCode": 200, "body": "ok"}
        data = json.loads(body)
    except Exception:
        return {"statusCode": 200, "body": "ok"}

    update = Update.de_json(data, None)
    app = _build_app()

    async def run():
        # init is required for processing updates
        await app.initialize()
        await app.process_update(update)
        await app.shutdown()

    asyncio.run(run())
    return {"statusCode": 200, "body": "ok"}

