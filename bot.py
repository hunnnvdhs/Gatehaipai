import os
import re
import asyncio
from typing import Iterable

from telegram import Update
from telegram.ext import Application, MessageHandler, ContextTypes, filters

from analyzer import SiteAnalyzer


BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
PROXY = os.getenv("TG_PROXY") or None

MAX_CONCURRENT_CHECKS = 20

URL_RE = re.compile(r"https?://[^\s<>\"]+", re.I)


def _normalize_url(s: str) -> str | None:
    s = (s or "").strip()
    if not s:
        return None
    if not s.startswith(("http://", "https://")):
        s = "https://" + s
    return s


def _extract_urls_from_text(text: str) -> list[str]:
    urls = set()
    for u in URL_RE.findall(text or ""):
        urls.add(u.strip().rstrip(").,;!\"'"))

    for line in (text or "").splitlines():
        line = line.strip()
        if not line or " " in line:
            continue
        if "." in line and not line.startswith("#") and not line.startswith("http"):
            urls.add(line)

    out = []
    for u in urls:
        nu = _normalize_url(u)
        if nu:
            out.append(nu)
    return sorted(set(out))


def _extract_urls_from_file_bytes(data: bytes) -> list[str]:
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        text = data.decode("latin-1", errors="ignore")
    return _extract_urls_from_text(text)


async def _scan_urls(urls: Iterable[str], analyzer: SiteAnalyzer) -> list[tuple[str, dict]]:
    sem = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    results: list[tuple[str, dict]] = []

    async def one(u: str):
        async with sem:
            try:
                r = await analyzer.analyze_site(u, proxy=PROXY)
            except Exception as e:
                r = {"status": f"Error: {e}", "gateway": "None Detected"}
            results.append((u, r))

    tasks = [asyncio.create_task(one(u)) for u in urls]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    return results


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


def _is_detected_gateway(r: dict) -> bool:
    return r.get("gateway") not in ("None Detected", "Generic / Private Gate 💳")


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

        await update.message.reply_text(f"Found {len(urls)} sites. Scanning with 20 threads...")
        scans = await _scan_urls(urls, analyzer)
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

    scans = await _scan_urls(urls, analyzer)
    detected = [(u, r) for (u, r) in scans if _is_detected_gateway(r)]
    if not detected:
        await update.message.reply_text("No gateway detected (or only generic payment keywords).")
        return

    msg = "\n\n".join(_format_result(u, r) for u, r in detected[:10])
    if len(detected) > 10:
        msg += f"\n\n(+{len(detected) - 10} more detected, upload as file for full output)"
    await update.message.reply_text(msg, disable_web_page_preview=True)


async def main():
    if not BOT_TOKEN:
        raise SystemExit("Set env var TG_BOT_TOKEN.")

    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(MessageHandler(filters.ALL, _handle_message))

    print("Bot running...")
    await app.run_polling(close_loop=False)


if __name__ == "__main__":
    asyncio.run(main())

