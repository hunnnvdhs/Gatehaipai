import os
import re
import asyncio
import io
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

def _split_gateways(gateway_str: str) -> list[str]:
    """
    analyzer returns a string like: "Stripe 💳, PayPal 💳"
    Normalize into ["Stripe", "PayPal"].
    """
    s = (gateway_str or "").replace("💳", "").strip()
    if not s or s == "None Detected":
        return []
    parts = [p.strip() for p in s.split(",")]
    return [p for p in parts if p]


def _build_summary(scans: list[tuple[str, dict]]) -> str:
    total = len(scans)
    detected = sum(1 for _, r in scans if _is_detected_gateway(r))
    skipped = total - detected
    return f"Total checked: {total} | Detected: {detected} | Skipped: {skipped}"


async def _edit_or_reply(msg, text: str):
    # msg is a telegram.Message returned by reply_text()
    try:
        await msg.edit_text(text, disable_web_page_preview=True)
    except Exception:
        try:
            await msg.reply_text(text, disable_web_page_preview=True)
        except Exception:
            return


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

async def _scan_urls_stream(
    urls: list[str],
    analyzer: SiteAnalyzer,
    on_result,
) -> list[tuple[str, dict]]:
    """
    Scan urls concurrently, but yield each result immediately via callback.
    """
    sem = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    results: list[tuple[str, dict]] = []

    async def one(u: str):
        async with sem:
            try:
                r = await analyzer.analyze_site(u, proxy=PROXY)
            except Exception as e:
                r = {"status": f"Error: {e}", "gateway": "None Detected", "security": "None Detected"}
            return (u, r)

    tasks = [asyncio.create_task(one(u)) for u in urls]
    for fut in asyncio.as_completed(tasks):
        u, r = await fut
        results.append((u, r))
        try:
            await on_result(u, r)
        except Exception:
            pass
    return results


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

        status_msg = await update.message.reply_text(
            f"Checking {len(urls)} sites… (20 threads)",
            disable_web_page_preview=True,
        )

        # For file uploads: send instant per-site results (one-by-one)
        gateway_counts: dict[str, int] = {}
        unsecured_rows: list[str] = []

        async def on_result(u: str, r: dict):
            gw = r.get("gateway", "None Detected")
            await update.message.reply_text(f"✅ Checked: {u} -> [{gw}]", disable_web_page_preview=True)

            # Only count "unsecured": no security detected
            if r.get("security", "None Detected") != "None Detected":
                return

            # Only count real gateways (skip None/Generic)
            if not _is_detected_gateway(r):
                return

            for name in _split_gateways(gw):
                gateway_counts[name] = gateway_counts.get(name, 0) + 1
            unsecured_rows.append(f"{u}\t{gw}\tsecurity=None Detected")

        scans = await _scan_urls_stream(urls, analyzer, on_result=on_result)
        detected = [(u, r) for (u, r) in scans if _is_detected_gateway(r)]
        summary = _build_summary(scans)
        if not detected:
            await _edit_or_reply(status_msg, f"{summary}\n\nNo gateways detected in this file.")
            return

        # After full file checked: send a counts file for "unsecured" only
        if gateway_counts:
            lines = []
            lines.append("Unsecured gateway counts (security == None Detected)")
            lines.append("")
            for k in sorted(gateway_counts.keys()):
                lines.append(f"{k}\t{gateway_counts[k]}")
            lines.append("")
            lines.append("Unsecured sites (url, gateway, security):")
            lines.extend(unsecured_rows[:2000])
            data = "\n".join(lines).encode("utf-8", errors="ignore")
            bio = io.BytesIO(data)
            bio.name = "unsecured_gateway_counts.txt"
            await update.message.reply_document(document=bio, caption="Unsecured gateway summary")

        # Final status message (single)
        await _edit_or_reply(status_msg, summary + "\n\nFile scan finished ✅")
        return

    text = update.message.text or update.message.caption or ""
    urls = _extract_urls_from_text(text)
    if not urls:
        await update.message.reply_text("Send a website URL, or upload a .txt file with one site per line.")
        return

    status_msg = await update.message.reply_text(
        f"Checking {len(urls)} site(s)…",
        disable_web_page_preview=True,
    )
    scans = await _scan_urls(urls, analyzer)
    detected = [(u, r) for (u, r) in scans if _is_detected_gateway(r)]
    summary = _build_summary(scans)
    if not detected:
        await _edit_or_reply(status_msg, f"{summary}\n\nNo gateway detected (or only generic payment keywords).")
        return

    msg = summary + "\n\n" + "\n\n".join(_format_result(u, r) for u, r in detected[:10])
    if len(detected) > 10:
        msg += f"\n(+{len(detected) - 10} more detected; upload as file for full output)"
    await _edit_or_reply(status_msg, msg)


def main():
    if not BOT_TOKEN:
        raise SystemExit("Set env var TG_BOT_TOKEN.")

    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(MessageHandler(filters.ALL, _handle_message))

    print("Bot running...")
    # run_polling manages its own event loop (don't wrap with asyncio.run)
    app.run_polling()


if __name__ == "__main__":
    main()

                           
