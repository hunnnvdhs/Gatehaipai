import os
import re
import asyncio
import io
import html
import json
import time
from typing import Iterable

from telegram import Update
from telegram.ext import Application, MessageHandler, CommandHandler, ContextTypes, filters

from analyzer import SiteAnalyzer


BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
PROXY = os.getenv("TG_PROXY") or None

# Owner + premium access control
OWNER_ID = int(os.getenv("OWNER_ID", "6021047784"))
PREMIUM_STORE_PATH = os.getenv("PREMIUM_STORE_PATH", "premium_users.json")

# Default per-chat concurrency for scans
DEFAULT_THREADS = int(os.getenv("DEFAULT_THREADS", "20"))

# Per-scan concurrency inside a chat (will be overridden by /set)
MAX_CONCURRENT_CHECKS = DEFAULT_THREADS
# Global limiter so 1 user doesn't overload the service
GLOBAL_MAX_CONCURRENT_CHECKS = int(os.getenv("GLOBAL_MAX_CONCURRENT_CHECKS", "60"))
GLOBAL_SEMAPHORE = asyncio.Semaphore(GLOBAL_MAX_CONCURRENT_CHECKS)

URL_RE = re.compile(r"https?://[^\s<>\"]+", re.I)

# Per-chat cancellation for mass scans
ACTIVE_SCANS: dict[int, dict] = {}
STRICT_CHATS: set[int] = set()
THREADS_BY_CHAT: dict[int, int] = {}

# premium storage: user_id -> expires_at_epoch (int)
PREMIUM_USERS: dict[str, int] = {}

# Per-chat file queue so users can send many files consecutively
FILE_QUEUES: dict[int, asyncio.Queue] = {}
QUEUE_WORKERS: dict[int, asyncio.Task] = {}


def _load_premium():
    global PREMIUM_USERS
    try:
        with open(PREMIUM_STORE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            PREMIUM_USERS = {str(k): int(v) for k, v in data.items()}
    except Exception:
        PREMIUM_USERS = {}


def _save_premium():
    try:
        with open(PREMIUM_STORE_PATH, "w", encoding="utf-8") as f:
            json.dump(PREMIUM_USERS, f, indent=2, sort_keys=True)
    except Exception:
        pass


def _is_owner(user_id: int | None) -> bool:
    return bool(user_id) and int(user_id) == OWNER_ID


def _is_premium(user_id: int | None) -> bool:
    if not user_id:
        return False
    if _is_owner(user_id):
        return True
    exp = PREMIUM_USERS.get(str(int(user_id)))
    if not exp:
        return False
    return int(exp) > int(time.time())


def _require_access(update: Update) -> bool:
    uid = update.effective_user.id if update.effective_user else None
    return _is_premium(uid)


def _threads_for_chat(chat_id: int) -> int:
    v = THREADS_BY_CHAT.get(chat_id, DEFAULT_THREADS)
    try:
        v = int(v)
    except Exception:
        v = DEFAULT_THREADS
    return max(1, min(v, 50))


async def _strict_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
    if not _require_access(update):
        await update.message.reply_text("Access denied.", reply_to_message_id=update.message.message_id)
        return
    chat_id = update.effective_chat.id if update.effective_chat else None
    if chat_id is None:
        return
    arg = (context.args[0].lower() if getattr(context, "args", None) and context.args else "").strip()
    if arg in ("on", "1", "true", "yes"):
        STRICT_CHATS.add(chat_id)
        await update.message.reply_text("STRICT mode: ON", reply_to_message_id=update.message.message_id)
        return
    if arg in ("off", "0", "false", "no"):
        STRICT_CHATS.discard(chat_id)
        await update.message.reply_text("STRICT mode: OFF", reply_to_message_id=update.message.message_id)
        return
    await update.message.reply_text("Usage: /strict on  OR  /strict off", reply_to_message_id=update.message.message_id)


async def _start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
    uid = update.effective_user.id if update.effective_user else None
    if not _is_premium(uid):
        await update.message.reply_text(
            "🔒 This bot is private.\n\nDM @xoxhunterxd for premium.",
            reply_to_message_id=update.message.message_id,
        )
        return

    chat_id = update.effective_chat.id if update.effective_chat else 0
    strict = chat_id in STRICT_CHATS
    threads = _threads_for_chat(chat_id)
    await update.message.reply_text(
        "✅ <b>Gateway Scanner Bot</b>\n"
        "━━━━━━━━━━━━━━━━━━\n"
        f"Mode: <b>{'STRICT' if strict else 'NORMAL'}</b>\n"
        f"Threads: <b>{threads}</b>\n"
        f"Global capacity: <b>{GLOBAL_MAX_CONCURRENT_CHECKS}</b>\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "\n"
        "<b>What this bot does</b>\n"
        "• Detects payment gateways (deep scan: HTML + scripts + iframes + endpoints)\n"
        "• Detects captcha/security layers\n"
        "• Finds checkout/cart/account pages (deep discovery)\n"
        "• Extracts public keys/sitekeys + privacy findings (redacted secrets)\n"
        "\n"
        "<b>How to use</b>\n"
        "• Send a site (domain or full URL)\n"
        "• Or upload a <b>.txt</b> file (1 site per line)\n"
        "\n"
        "<b>During file scan</b>\n"
        "• Live progress UI updates\n"
        "• Sends a message only when a gateway is detected\n"
        "• Sends final report files at the end\n",
        parse_mode="HTML",
        disable_web_page_preview=True,
        reply_to_message_id=update.message.message_id,
    )


async def _set_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
    uid = update.effective_user.id if update.effective_user else None
    if not _is_owner(uid):
        await update.message.reply_text("Owner only.", reply_to_message_id=update.message.message_id)
        return
    chat_id = update.effective_chat.id if update.effective_chat else 0
    if not getattr(context, "args", None) or not context.args:
        await update.message.reply_text("Usage: /set 20", reply_to_message_id=update.message.message_id)
        return
    try:
        v = int(context.args[0])
    except Exception:
        await update.message.reply_text("Usage: /set 20", reply_to_message_id=update.message.message_id)
        return
    THREADS_BY_CHAT[chat_id] = max(1, min(v, 50))
    await update.message.reply_text(
        f"Threads set to {THREADS_BY_CHAT[chat_id]} for this chat.",
        reply_to_message_id=update.message.message_id,
    )


async def _add_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
    uid = update.effective_user.id if update.effective_user else None
    if not _is_owner(uid):
        await update.message.reply_text("Owner only.", reply_to_message_id=update.message.message_id)
        return
    if not getattr(context, "args", None) or len(context.args) < 2:
        await update.message.reply_text("Usage: /add <user_id> <days>", reply_to_message_id=update.message.message_id)
        return
    try:
        target = int(context.args[0])
        days = int(context.args[1])
    except Exception:
        await update.message.reply_text("Usage: /add <user_id> <days>", reply_to_message_id=update.message.message_id)
        return
    expires = int(time.time()) + max(1, days) * 86400
    PREMIUM_USERS[str(target)] = expires
    _save_premium()
    await update.message.reply_text(
        f"Premium added: {target} for {days} day(s).",
        reply_to_message_id=update.message.message_id,
    )


async def _rem_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
    uid = update.effective_user.id if update.effective_user else None
    if not _is_owner(uid):
        await update.message.reply_text("Owner only.", reply_to_message_id=update.message.message_id)
        return
    if not getattr(context, "args", None) or len(context.args) < 1:
        await update.message.reply_text("Usage: /rem <user_id>", reply_to_message_id=update.message.message_id)
        return
    try:
        target = int(context.args[0])
    except Exception:
        await update.message.reply_text("Usage: /rem <user_id>", reply_to_message_id=update.message.message_id)
        return
    PREMIUM_USERS.pop(str(target), None)
    _save_premium()
    await update.message.reply_text(
        f"Premium removed: {target}",
        reply_to_message_id=update.message.message_id,
    )


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

def _ui_status(total: int, done: int, detected: int, last_gw: str, strict: bool, threads: int) -> str:
    mode = "STRICT" if strict else "NORMAL"
    last_gw = last_gw or "-"
    return (
        f"<b>Checking…</b> ({mode})\n"
        f"Threads: <b>{threads}</b> | Global limit: <b>{GLOBAL_MAX_CONCURRENT_CHECKS}</b>\n"
        f"Progress: <b>{done}/{total}</b> | Detected: <b>{detected}</b>\n"
        f"Last gateway: <b>{html.escape(last_gw)}</b>"
    )

def _ui_detect_card(url: str, r: dict) -> str:
    gw = r.get("gateway", "None Detected")
    chk = r.get("checkout_link", "Not Found")
    sec = r.get("security", "None Detected")
    cap = r.get("captcha", "None Detected")
    status = r.get("status", "Success")
    conf = r.get("gateway_confidence") or {}
    keys = r.get("keys") or []
    privacy = r.get("privacy_findings") or []

    conf_pairs = []
    if isinstance(conf, dict):
        for name in _split_gateways(gw):
            lvl = conf.get(name)
            if lvl:
                conf_pairs.append(f"{name}={lvl}")

    # "Blockquote-like" premium UI using a boxed <pre> block
    box = []
    box.append("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    box.append(f"┃ URL: {url}")
    box.append(f"┃ Gateway: {gw}")
    box.append(f"┃ Confidence: {', '.join(conf_pairs) if conf_pairs else '-'}")
    box.append(f"┃ Checkout: {chk}")
    box.append(f"┃ Security: {sec}")
    box.append(f"┃ Captcha: {cap}")
    box.append(f"┃ Status: {status}")
    box.append("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    extras = []
    if keys:
        extras.append("Keys:")
        for k in keys[:20]:
            extras.append(f"- {k}")
        if len(keys) > 20:
            extras.append(f"- (+{len(keys) - 20} more)")
    if privacy:
        if extras:
            extras.append("")
        extras.append("Privacy findings:")
        for p in privacy[:15]:
            extras.append(f"- {p}")
        if len(privacy) > 15:
            extras.append(f"- (+{len(privacy) - 15} more)")

    pre_body = "\n".join(box + ([""] + extras if extras else []))
    return "✅ <b>Detected</b>\n<pre>" + html.escape(pre_body) + "</pre>"


async def _edit_or_reply(msg, text: str):
    # msg is a telegram.Message returned by reply_text()
    try:
        await msg.edit_text(text, disable_web_page_preview=True, parse_mode="HTML")
    except Exception:
        try:
            await msg.reply_text(text, disable_web_page_preview=True, parse_mode="HTML")
        except Exception:
            return


async def _reply_in_chunks(update: Update, text: str):
    if not update.message:
        return
    limit = 3500
    if len(text) <= limit:
        await update.message.reply_text(
            text,
            disable_web_page_preview=True,
            parse_mode="HTML",
            reply_to_message_id=update.message.message_id,
        )
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
        await update.message.reply_text(
            p,
            disable_web_page_preview=True,
            parse_mode="HTML",
            reply_to_message_id=update.message.message_id,
        )

async def _scan_urls_stream(
    urls: list[str],
    analyzer: SiteAnalyzer,
    on_result,
    cancel_event: asyncio.Event | None = None,
    strict: bool = False,
    threads: int = DEFAULT_THREADS,
) -> list[tuple[str, dict]]:
    """
    Scan urls concurrently, but yield each result immediately via callback.
    """
    sem = asyncio.Semaphore(max(1, int(threads)))
    results: list[tuple[str, dict]] = []

    async def one(u: str):
        if cancel_event and cancel_event.is_set():
            return (u, {"status": "Cancelled", "gateway": "None Detected", "security": "None Detected"})
        async with sem:
            async with GLOBAL_SEMAPHORE:
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
    if not _require_access(update):
        await update.message.reply_text("Access denied.", reply_to_message_id=update.message.message_id)
        return
    chat_id = update.effective_chat.id if update.effective_chat else None
    if chat_id is None:
        return

    scan = ACTIVE_SCANS.get(chat_id)
    if not scan:
        await update.message.reply_text("No active scan to stop.")
        return

    scan["cancel"].set()
    await update.message.reply_text("🛑 Stopping current scan…", reply_to_message_id=update.message.message_id)
    try:
        status_msg = scan.get("status_msg")
        if status_msg:
            await _edit_or_reply(status_msg, "🛑 Scan stopped by user.")
    except Exception:
        pass

    # Clear queued files too
    q = FILE_QUEUES.get(chat_id)
    if q:
        try:
            while not q.empty():
                q.get_nowait()
                q.task_done()
        except Exception:
            pass


async def _handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return

    if not _require_access(update):
        await update.message.reply_text(
            "🔒 This bot is private.\n\nDM @xoxhunterxd for premium.",
            reply_to_message_id=update.message.message_id,
        )
        return

    analyzer = SiteAnalyzer()
    chat_id = update.effective_chat.id if update.effective_chat else 0
    strict_mode = chat_id in STRICT_CHATS
    threads = _threads_for_chat(chat_id)

    doc = update.message.document
    if doc:
        # Queue files per chat (supports 50+ consecutive file uploads)
        try:
            f = await context.bot.get_file(doc.file_id)
            data = await f.download_as_bytearray()
            urls = _extract_urls_from_file_bytes(bytes(data))
        except Exception:
            urls = []

        if not urls:
            await update.message.reply_text("No URLs found in file.", reply_to_message_id=update.message.message_id)
            return

        q = FILE_QUEUES.get(chat_id)
        if not q:
            q = asyncio.Queue()
            FILE_QUEUES[chat_id] = q

        # Put this file's payload into queue
        await q.put(
            {
                "urls": urls,
                "reply_to": update.message.message_id,
                "strict": strict_mode,
                "threads": threads,
            }
        )

        queued = q.qsize()
        await update.message.reply_text(
            f"📥 Added to queue. Files queued: {queued}",
            reply_to_message_id=update.message.message_id,
        )

        # Start a worker if not running
        if chat_id not in QUEUE_WORKERS or QUEUE_WORKERS[chat_id].done():
            QUEUE_WORKERS[chat_id] = asyncio.create_task(_queue_worker(chat_id, context))

        return

    text = update.message.text or update.message.caption or ""
    urls = _extract_urls_from_text(text)
    if not urls:
        await update.message.reply_text(
            "Send a website URL, or upload a .txt file with one site per line.\nCommands: /strict on|off, /stop",
            reply_to_message_id=update.message.message_id,
        )
        return

    status_msg = await update.message.reply_text(
        _ui_status(total=len(urls), done=0, detected=0, last_gw="", strict=strict_mode, threads=threads),
        disable_web_page_preview=True,
        parse_mode="HTML",
        reply_to_message_id=update.message.message_id,
    )
    cancel_event = asyncio.Event()
    ACTIVE_SCANS[update.effective_chat.id] = {"cancel": cancel_event, "status_msg": status_msg}
    # small scans: reuse stream scanner for correct strict behavior
    tmp: list[tuple[str, dict]] = []
    async def on_small(u: str, r: dict):
        tmp.append((u, r))
    await _scan_urls_stream(urls, analyzer, on_result=on_small, strict=strict_mode, threads=threads)
    scans = tmp
    ACTIVE_SCANS.pop(update.effective_chat.id, None)
    detected = [(u, r) for (u, r) in scans if _is_detected_gateway(r)]
    summary = _build_summary(scans)
    if not detected:
        await _edit_or_reply(status_msg, f"<b>{html.escape(summary)}</b>\n\nNo gateway detected.")
        return

    # For single message scans, send a clean combined output
    blocks = [_ui_detect_card(u, r) for u, r in detected[:10]]
    msg = f"<b>{html.escape(summary)}</b>\n\n" + "\n\n".join(blocks)
    if len(detected) > 10:
        msg += f"\n\n(+{len(detected) - 10} more detected; upload as file for full output)"
    await _edit_or_reply(status_msg, msg)


async def _queue_worker(chat_id: int, context: ContextTypes.DEFAULT_TYPE):
    """
    Process queued file scans for a chat sequentially.
    Allows 50+ files to be dropped consecutively without blocking other chats.
    """
    q = FILE_QUEUES.get(chat_id)
    if not q:
        return

    while True:
        try:
            job = await q.get()
        except Exception:
            return
        try:
            urls = job.get("urls") or []
            reply_to = int(job.get("reply_to") or 0)
            strict_mode = bool(job.get("strict"))
            threads = int(job.get("threads") or DEFAULT_THREADS)

            analyzer = SiteAnalyzer()

            # status message for this job
            status_msg = await context.bot.send_message(
                chat_id=chat_id,
                text=_ui_status(total=len(urls), done=0, detected=0, last_gw="", strict=strict_mode, threads=threads),
                parse_mode="HTML",
                disable_web_page_preview=True,
                reply_to_message_id=reply_to if reply_to else None,
            )

            cancel_event = asyncio.Event()
            ACTIVE_SCANS[chat_id] = {"cancel": cancel_event, "status_msg": status_msg}

            gateway_counts: dict[str, int] = {}
            unsecured_rows: list[str] = []
            all_rows: list[str] = []
            progress = {"done": 0, "detected": 0, "last": ""}
            progress_lock = asyncio.Lock()
            last_edit = {"t": 0.0}

            async def on_result(u: str, r: dict):
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

                async with progress_lock:
                    progress["done"] += 1
                    if is_detected:
                        progress["detected"] += 1
                        progress["last"] = gw
                    done = progress["done"]
                    detected_n = progress["detected"]
                    last_gw = progress["last"]

                now = time.time()
                if now - last_edit["t"] > 0.6 or done == len(urls):
                    last_edit["t"] = now
                    await _edit_or_reply(
                        status_msg,
                        _ui_status(total=len(urls), done=done, detected=detected_n, last_gw=last_gw, strict=strict_mode, threads=threads),
                    )

                if is_detected:
                    await context.bot.send_message(
                        chat_id=chat_id,
                        text=_ui_detect_card(u, r),
                        parse_mode="HTML",
                        disable_web_page_preview=True,
                        reply_to_message_id=reply_to if reply_to else None,
                    )

                all_rows.append(f"{u}\t{gw}\t{chk}\t{sec}\t{cap}\t{conf_short}")

                if sec != "None Detected":
                    return
                if not is_detected:
                    return
                for name in _split_gateways(gw):
                    gateway_counts[name] = gateway_counts.get(name, 0) + 1
                unsecured_rows.append(f"{u}\t{gw}\t{chk}\t{sec}\t{cap}\t{conf_short}")

            scans = await _scan_urls_stream(urls, analyzer, on_result=on_result, cancel_event=cancel_event, strict=strict_mode, threads=threads)
            ACTIVE_SCANS.pop(chat_id, None)

            if cancel_event.is_set():
                await _edit_or_reply(
                    status_msg,
                    f"🛑 <b>Stopped</b>\nProgress: <b>{progress['done']}/{len(urls)}</b> | Detected: <b>{progress['detected']}</b>",
                )
                continue

            detected = [(u, r) for (u, r) in scans if _is_detected_gateway(r)]
            summary = _build_summary(scans)
            if not detected:
                await _edit_or_reply(status_msg, f"<b>{html.escape(summary)}</b>\n\nNo gateways detected in this file.")
                continue

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
                await context.bot.send_document(chat_id=chat_id, document=bio, caption="Unsecured gateway summary")

            report_lines = []
            report_lines.append("Full scan report (all sites)")
            report_lines.append("Columns: url\tgateway\tcheckout\tsecurity\tcaptcha\tconfidence")
            report_lines.append("")
            report_lines.extend(all_rows)
            report_data = "\n".join(report_lines).encode("utf-8", errors="ignore")
            report_bio = io.BytesIO(report_data)
            report_bio.name = "full_scan_report.txt"
            await context.bot.send_document(chat_id=chat_id, document=report_bio, caption="Full scan report")

            await _edit_or_reply(status_msg, f"<b>{html.escape(summary)}</b>\n\nFile scan finished ✅")

        finally:
            try:
                q.task_done()
            except Exception:
                pass

        # stop worker when queue is empty
        if q.empty():
            break


def main():
    if not BOT_TOKEN:
        raise SystemExit("Set env var TG_BOT_TOKEN.")

    _load_premium()

    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", _start_cmd))
    app.add_handler(CommandHandler("strict", _strict_cmd))
    app.add_handler(CommandHandler("set", _set_cmd))
    app.add_handler(CommandHandler("stop", _stop_cmd))
    app.add_handler(CommandHandler("add", _add_cmd))
    app.add_handler(CommandHandler("rem", _rem_cmd))
    app.add_handler(MessageHandler(filters.ALL, _handle_message))

    print("Bot running...")
    # run_polling manages its own event loop (don't wrap with asyncio.run)
    app.run_polling()


if __name__ == "__main__":
    main()

