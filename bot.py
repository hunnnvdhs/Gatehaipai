import os
import re
import asyncio
import io
from typing import Iterable

from telegram import Update
from telegram.ext import Application, MessageHandler, CommandHandler, ContextTypes, filters

from analyzer import SiteAnalyzer


BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
PROXY = os.getenv("TG_PROXY") or None

MAX_CONCURRENT_CHECKS = 20

URL_RE = re.compile(r"https?://[^\s<>\"]+", re.I)

# Per-chat cancellation for mass scans
ACTIVE_SCANS: dict[int, dict] = {}
STRICT_CHATS: set[int] = set()


async def _strict_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
    chat_id = update.effective_chat.id if update.effective_chat else None
    if chat_id is None:
        return
    arg = (context.args[0].lower() if getattr(context, "args", None) and context.args else "").strip()
    if arg in ("on", "1", "true", "yes"):
        STRICT_CHATS.add(chat_id)
        await update.message.reply_text("STRICT mode: ON")
        return
    if arg in ("off", "0", "false", "no"):
        STRICT_CHATS.discard(chat_id)
        await update.message.reply_text("STRICT mode: OFF")
        return
    await update.message.reply_text("Usage: /strict on  OR  /strict off")


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

    async def one(u: str, strict: bool):
        async with sem:
            try:
                r = await analyzer.analyze_site(u, proxy=PROXY, strict=strict)
            except Exception as e:
                r = {"status": f"Error: {e}", "gateway": "None Detected"}
            results.append((u, r))

    # NOTE: strict flag is decided per chat in _handle_message
    # This function is used only for non-file (small) scans.
    tasks = [asyncio.create_task(one(u, False)) for u in urls]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    return results


def _format_result(url: str, r: dict) -> str:
    gw = r.get("gateway", "None Detected")
    status = r.get("status", "Success")
    chk = r.get("checkout_link", "Not Found")
    sec = r.get("security", "None Detected")
    cap = r.get("captcha", "None Detected")
    conf = r.get("gateway_confidence") or {}
    keys = r.get("keys") or []
    privacy = r.get("privacy_findings") or []

    conf_str = ""
    if isinstance(conf, dict) and conf:
        # show only gateways present in gw string
        pairs = []
        for name in _split_gateways(gw):
            lvl = conf.get(name)
            if lvl:
                pairs.append(f"{name}={lvl}")
        if pairs:
            conf_str = "\n" + "🎯 Confidence: " + ", ".join(pairs)

    keys_str = ""
    if keys:
        keys_str = "\n" + "🔑 Keys:\n" + "\n".join(f"- {k}" for k in keys[:20])
        if len(keys) > 20:
            keys_str += f"\n- (+{len(keys) - 20} more)"

    privacy_str = ""
    if privacy:
        privacy_str = "\n" + "🕵️ Privacy findings:\n" + "\n".join(f"- {p}" for p in privacy[:15])
        if len(privacy) > 15:
            privacy_str += f"\n- (+{len(privacy) - 15} more)"

    return (
        f"🔗 {url}\n"
        f"💳 Gateway: {gw}\n"
        f"🛒 Checkout: {chk}\n"
        f"🛡️ Security: {sec}\n"
        f"🤖 Captcha: {cap}\n"
        f"🛰️ Status: {status}"
        f"{conf_str}"
        f"{keys_str}"
        f"{privacy_str}\n"
    )


def _is_detected_gateway(r: dict) -> bool:
    gw = r.get("gateway")
    if not gw:
        return False
    # If it's generic but includes a likely label, treat it as detected
    if gw.startswith("Generic / Private Gate") and "(" in gw and "likely" in gw.lower():
        return True
    return gw not in ("None Detected", "Generic / Private Gate 💳")

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
    cancel_event: asyncio.Event | None = None,
    strict: bool = False,
) -> list[tuple[str, dict]]:
    """
    Scan urls concurrently, but yield each result immediately via callback.
    """
    sem = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    results: list[tuple[str, dict]] = []

    async def one(u: str):
        if cancel_event and cancel_event.is_set():
            return (u, {"status": "Cancelled", "gateway": "None Detected", "security": "None Detected"})
        async with sem:
            try:
                r = await analyzer.analyze_site(u, proxy=PROXY, strict=strict)
            except Exception as e:
                r = {"status": f"Error: {e}", "gateway": "None Detected", "security": "None Detected"}
            return (u, r)

    tasks = [asyncio.create_task(one(u)) for u in urls]
    try:
        for fut in asyncio.as_completed(tasks):
            if cancel_event and cancel_event.is_set():
                break
            u, r = await fut
            results.append((u, r))
            if cancel_event and cancel_event.is_set():
                break
            try:
                await on_result(u, r)
            except Exception:
                pass
    finally:
        # Cancel remaining tasks if stopped
        if cancel_event and cancel_event.is_set():
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    return results


async def _stop_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
    chat_id = update.effective_chat.id if update.effective_chat else None
    if chat_id is None:
        return

    scan = ACTIVE_SCANS.get(chat_id)
    if not scan:
        await update.message.reply_text("No active scan to stop.")
        return

    scan["cancel"].set()
    await update.message.reply_text("🛑 Stopping current scan…")
    try:
        status_msg = scan.get("status_msg")
        if status_msg:
            await _edit_or_reply(status_msg, "🛑 Scan stopped by user.")
    except Exception:
        pass


async def _handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return

    analyzer = SiteAnalyzer()
    chat_id = update.effective_chat.id if update.effective_chat else 0
    strict_mode = chat_id in STRICT_CHATS

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
        cancel_event = asyncio.Event()
        ACTIVE_SCANS[update.effective_chat.id] = {"cancel": cancel_event, "status_msg": status_msg}

        # For file uploads: send instant per-site results (one-by-one)
        gateway_counts: dict[str, int] = {}
        unsecured_rows: list[str] = []
        all_rows: list[str] = []
        progress = {"done": 0, "detected": 0, "last": ""}
        progress_lock = asyncio.Lock()
        last_edit = {"t": 0.0}

        async def on_result(u: str, r: dict):
            import time

            is_detected = _is_detected_gateway(r)
            gw = r.get("gateway", "None Detected")
            cap = r.get("captcha", "None Detected")
            sec = r.get("security", "None Detected")
            chk = r.get("checkout_link", "Not Found")
            conf = r.get("gateway_confidence") or {}
            conf_pairs = []
            if isinstance(conf, dict):
                for name in _split_gateways(gw):
                    lvl = conf.get(name)
                    if lvl:
                        conf_pairs.append(f"{name}={lvl}")
            conf_short = ", ".join(conf_pairs) if conf_pairs else ""

            # update live UI (edit the main status message)
            async with progress_lock:
                progress["done"] += 1
                if is_detected:
                    progress["detected"] += 1
                    progress["last"] = gw
                done = progress["done"]
                detected_n = progress["detected"]
                last_gw = progress["last"]

            # edit at most ~2 times/sec to avoid Telegram rate limits
            now = time.time()
            if now - last_edit["t"] > 0.6 or done == len(urls):
                last_edit["t"] = now
                await _edit_or_reply(
                    status_msg,
                    "Checking… (20 threads)\n"
                    f"Progress: {done}/{len(urls)} | Detected: {detected_n}\n"
                    f"Last gateway: {last_gw or '-'}",
                )

            # Only send per-site message when detected
            if is_detected:
                # Send full info block when detected
                await update.message.reply_text(
                    "✅ Detected\n\n" + _format_result(u, r),
                    disable_web_page_preview=True,
                )

            # Accumulate all results for final report file
            # tab-separated for easy parsing
            all_rows.append(f"{u}\t{gw}\t{chk}\t{sec}\t{cap}\t{conf_short}")

            # Only count "unsecured": no security detected
            if sec != "None Detected":
                return

            # Only count real gateways (skip None/Generic)
            if not is_detected:
                return

            for name in _split_gateways(gw):
                gateway_counts[name] = gateway_counts.get(name, 0) + 1
            unsecured_rows.append(f"{u}\t{gw}\t{chk}\t{sec}\t{cap}\t{conf_short}")

        scans = await _scan_urls_stream(urls, analyzer, on_result=on_result, cancel_event=cancel_event, strict=strict_mode)
        # clear active scan
        ACTIVE_SCANS.pop(update.effective_chat.id, None)

        if cancel_event.is_set():
            await _edit_or_reply(status_msg, f"Stopped ✅\nProgress: {progress['done']}/{len(urls)} | Detected: {progress['detected']}")
            return
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
            lines.append("Unsecured detected sites (url, gateway, checkout, security, captcha, confidence):")
            lines.extend(unsecured_rows[:5000])
            data = "\n".join(lines).encode("utf-8", errors="ignore")
            bio = io.BytesIO(data)
            bio.name = "unsecured_gateway_counts.txt"
            await update.message.reply_document(document=bio, caption="Unsecured gateway summary")

        # Final report file: all sites with all info
        report_lines = []
        report_lines.append("Full scan report (all sites)")
        report_lines.append("Columns: url\tgateway\tcheckout\tsecurity\tcaptcha\tconfidence")
        report_lines.append("")
        report_lines.extend(all_rows)
        report_data = "\n".join(report_lines).encode("utf-8", errors="ignore")
        report_bio = io.BytesIO(report_data)
        report_bio.name = "full_scan_report.txt"
        await update.message.reply_document(document=report_bio, caption="Full scan report")

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
    cancel_event = asyncio.Event()
    ACTIVE_SCANS[update.effective_chat.id] = {"cancel": cancel_event, "status_msg": status_msg}
    # small scans: reuse stream scanner for correct strict behavior
    tmp: list[tuple[str, dict]] = []
    async def on_small(u: str, r: dict):
        tmp.append((u, r))
    await _scan_urls_stream(urls, analyzer, on_result=on_small, strict=strict_mode)
    scans = tmp
    ACTIVE_SCANS.pop(update.effective_chat.id, None)
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
    app.add_handler(CommandHandler("strict", _strict_cmd))
    app.add_handler(CommandHandler("stop", _stop_cmd))
    app.add_handler(MessageHandler(filters.ALL, _handle_message))

    print("Bot running...")
    # run_polling manages its own event loop (don't wrap with asyncio.run)
    app.run_polling()


if __name__ == "__main__":
    main()

