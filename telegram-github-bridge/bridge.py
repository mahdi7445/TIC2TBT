# -*- coding: utf-8 -*-
"""Telegram <-> GitHub relay for the TIC2TOOBIT admin/control plane."""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path

import requests
from cryptography.fernet import Fernet

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("telegram-github-bridge")

TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
CHANNEL_ID = str(os.environ["TELEGRAM_CHANNEL_ID"])
ADMIN_CHAT_ID = str(os.environ["TELEGRAM_ADMIN_CHAT_ID"])
# Same master key user_store.py uses on the Windows executor. Must be set as
# a GitHub Actions secret for this workflow (never committed) - it is what
# lets a subscriber's raw API key/secret be encrypted here, BEFORE the
# /connect command is ever written to commands.jsonl, so the plaintext key
# never touches this public repo even for one commit. If this secret is
# missing, /connect is refused outright rather than ever relaying plaintext.
USER_VAULT_MASTER_KEY = os.environ.get("USER_VAULT_MASTER_KEY", "")
# The only commands a non-admin (multi-tenant subscriber) chat may ever
# trigger. Everything else from a non-admin chat_id is silently ignored,
# exactly like today's behavior for any stranger. This mirrors (but does not
# replace - see caller_chat_id in executor.py) the SELF_SERVICE_COMMANDS
# allow-list enforced independently on the executor side.
SELF_SERVICE_COMMANDS = {
    "/start", "/help", "/menu", "/terms", "/accept", "/decline", "/plans", "/prices", "/subscribe", "/cancelpay", "/paid",
    "/usediscount", "/cleardiscount", "/invite", "/claimtrial", "/mysignal", "/mycancelentry",
    "/connect_enc", "/connectguide", "/support", "/mysubscription", "/mystatus",
    "/mytrades", "/myhistory", "/mypnl", "/myexport", "/mybalance", "/myclose", "/mycloseall", "/mypause", "/myresume",
    "/mysettings", "/myvalue", "/myset", "/myrisk", "/reqcap", "/myautoexit", "/mydailyreport",
    "/myliqsafe", "/myliqadd", "/mycolall", "/myliqauto", "/myliqguard", "/disconnect", "/myconfirmclose", "/mydismissclose",
    "/myfixall", "/myprotection", "/rec", "/myrecapply", "/setupbudget", "/more",
}
API = f"https://api.telegram.org/bot{TOKEN}"

SIGNALS = Path("signals.jsonl")
COMMANDS = Path("commands.jsonl")
OUTBOX = Path("outbox.jsonl")
BRIDGE_STATE = Path("bridge_state.json")
HEARTBEAT_FILE = Path("heartbeat.json")
# How stale the Windows executor's heartbeat can be before bridge.py assumes
# it's down and alerts directly (well above HEARTBEAT_INTERVAL_SECONDS=60 in
# executor.py, so normal write jitter/relay delay never false-alarms).
HEARTBEAT_STALE_SECONDS = int(os.environ.get("HEARTBEAT_STALE_SECONDS", "360"))
MAX_LINES = int(os.environ.get("MAX_RELAY_LINES", "5000"))
RUNTIME_SECONDS = int(os.environ.get("BRIDGE_RUNTIME_SECONDS", "275"))
# Telegram's getUpdates call blocks for up to this many seconds waiting for a
# new update before returning empty - so it, not the sleep() at the bottom of
# the loop, is what actually sets the loop's cadence. The previous 25s value
# meant push/pull only really happened once every ~25s while idle, which
# quietly capped outbox-relay latency at ~25s no matter how tight the push/
# pull intervals below were set. 5s keeps genuine long-polling (still much
# cheaper than a plain poll loop) while letting push/pull run close to the
# cadence they're actually configured for.
LONG_POLL_SECONDS = int(os.environ.get("TELEGRAM_LONG_POLL_SECONDS", "3"))

# Push/pull cadence inside the run loop. Previously both only happened once,
# at the very end of the whole ~275s run - a command received right after the
# loop started could sit unpushed (and therefore invisible to the Windows
# executor) for most of that window, and any outbox message the executor
# pushed to GitHub mid-run was only picked up by the *next* bridge.py run's
# fresh checkout. That combination is what made admin commands take minutes
# to answer. Pushing/pulling every few seconds instead keeps both directions
# close to real time without hammering the GitHub API.
PUSH_MIN_INTERVAL_SECONDS = float(os.environ.get("PUSH_MIN_INTERVAL_SECONDS", "0.7"))
PULL_MIN_INTERVAL_SECONDS = float(os.environ.get("PULL_MIN_INTERVAL_SECONDS", "2"))

# Self-dispatch: queue the next run of this same workflow immediately instead
# of relying solely on GitHub's "*/5 * * * *" cron, which this repository's
# own Actions history shows firing anywhere from ~5 minutes to several hours
# apart under load - not the steady 5-minute cadence the architecture assumes.
# The cron trigger in bridge.yml is left in place as an external safety net in
# case this chain is ever broken (e.g. the token is briefly invalid).
GH_DISPATCH_TOKEN = os.environ.get("GH_DISPATCH_TOKEN", "")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "")
GITHUB_REF_NAME = os.environ.get("GITHUB_REF_NAME", "main")
BRIDGE_WORKFLOW_FILE = os.environ.get("BRIDGE_WORKFLOW_FILE", "bridge.yml")

# Slash commands are only a convenience now - everything is reachable with buttons.
USER_BOT_COMMANDS = [
    {"command": "start", "description": "Start / back to my menu"},
    {"command": "menu", "description": "My menu"},
    {"command": "help", "description": "Guide"},
]
BOT_COMMANDS = [
    {"command": "start", "description": "Admin menu"},
    {"command": "menu", "description": "Admin menu"},
]


def load_state() -> dict:
    if not BRIDGE_STATE.exists():
        return {"telegram_update_offset": 0, "outbox_lines_sent": 0}
    try:
        return json.loads(BRIDGE_STATE.read_text(encoding="utf-8"))
    except Exception:
        return {"telegram_update_offset": 0, "outbox_lines_sent": 0}


def save_state(state: dict) -> None:
    tmp = BRIDGE_STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(BRIDGE_STATE)


def append_lines(path: Path, new_lines: list[str]) -> None:
    if not new_lines:
        return
    old = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    combined = (old + [x.rstrip("\n") for x in new_lines])[-MAX_LINES:]
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("\n".join(combined) + "\n", encoding="utf-8")
    tmp.replace(path)


def ensure_runtime_files() -> None:
    for path in (SIGNALS, COMMANDS, OUTBOX):
        if not path.exists():
            path.write_text("", encoding="utf-8")


def telegram_call(method: str, payload: dict | None = None) -> dict:
    r = requests.post(API + "/" + method, json=payload or {}, timeout=20)
    r.raise_for_status()
    body = r.json()
    if not body.get("ok"):
        raise RuntimeError(f"Telegram API error: {body}")
    return body


# Emoji that Telegram draws as a flat text glyph unless they carry the emoji variation selector (U+FE0F). Mixing the
# two forms made some cards look different from others, so every outgoing text/button goes through emoji_norm().
_TEXT_EMOJI = "\u00a9\u00ae\u203c\u2049\u2122\u2139\u21a9\u21aa\u23ed\u23ee\u23ef\u23f1\u23f2\u23f8\u23f9\u23fa\u25b6\u25c0\u25ab\u25aa\u2696\u2699\u26a0\u267b\u2709\u270d\u270f\u2714\u2716\u27a1\u2b05\u2b06\u2b07\u2194\u2195\u2196\u2197\u2198\u2199\u2601\u2602\u2611\u2618\u261d\u2620\u2622\u2623\u263a\u2640\u2642\u2660\u2663\u2665\u2666\u2668\u267e\u267f\u2692\u2694\u2695\u2697\u269b\u269c\u26a7\u26b0\u26b1\u26c8\u26cf\u26d1\u26d3\u26e9\u26f0\u26f1\u26f4\u26f7\u26f8\u26f9\u2721\u2733\u2734\u2744\u2747\u2763\u2764\U0001f3cb\U0001f3cc\U0001f3d4\U0001f3d5\U0001f3d6\U0001f3d7\U0001f3d8\U0001f3d9\U0001f3da\U0001f3db\U0001f3dc\U0001f3dd\U0001f3de\U0001f3df\U0001f39f\U0001f396\U0001f397\U0001f399\U0001f39a\U0001f39b\U0001f3a5\U0001f3de\U0001f441\U0001f4fd\U0001f549\U0001f54a\U0001f56f\U0001f570\U0001f573\U0001f574\U0001f575\U0001f576\U0001f577\U0001f578\U0001f579\U0001f587\U0001f58a\U0001f58b\U0001f58c\U0001f58d\U0001f590\U0001f5a5\U0001f5a8\U0001f5b1\U0001f5b2\U0001f5bc\U0001f5c2\U0001f5c3\U0001f5c4\U0001f5d1\U0001f5d2\U0001f5d3\U0001f5dc\U0001f5dd\U0001f5de\U0001f5e1\U0001f5e3\U0001f5e8\U0001f5ef\U0001f5f3\U0001f5fa\U0001f6cb\U0001f6cd\U0001f6ce\U0001f6cf\U0001f6e0\U0001f6e1\U0001f6e2\U0001f6e3\U0001f6e4\U0001f6e5\U0001f6e9\U0001f6f0\U0001f6f3"
_TEXT_EMOJI_RE = re.compile("([" + _TEXT_EMOJI + "])(?!\ufe0f)")


def emoji_norm(text):
    """One look for every emoji: text-style symbols get U+FE0F, and the two hourglasses collapse into one."""
    if not isinstance(text, str):
        return text
    return _TEXT_EMOJI_RE.sub("\\1\ufe0f", text.replace("\u231b", "\u23f3"))


def send_message(text: str, inline_keyboard=None, reply_keyboard=None, reply_to_message_id=None, chat_id=None,
                 remove_keyboard: bool = False, silent: bool = False):
    payload = {"chat_id": chat_id or ADMIN_CHAT_ID, "text": emoji_norm(str(text))[:4000], "disable_web_page_preview": True}
    if inline_keyboard is not None:
        inline_keyboard = [[({**b, "text": emoji_norm(b["text"])} if isinstance(b, dict) and isinstance(b.get("text"), str) else b) for b in row] for row in inline_keyboard]
    if silent:
        payload["disable_notification"] = True
    if inline_keyboard is not None:
        payload["reply_markup"] = {"inline_keyboard": inline_keyboard}
    elif reply_keyboard is not None:
        payload["reply_markup"] = {"keyboard": reply_keyboard, "resize_keyboard": True, "is_persistent": True}
    elif remove_keyboard:
        payload["reply_markup"] = {"remove_keyboard": True}
    if reply_to_message_id:
        payload["reply_to_message_id"] = reply_to_message_id
        # Never let a missing/too-old root message silently swallow this one -
        # Telegram just sends it as a normal message instead of erroring out.
        payload["allow_sending_without_reply"] = True
    body = telegram_call("sendMessage", payload)
    try:
        return body.get("result", {}).get("message_id")
    except Exception:
        return None


def send_photo_message(photo_id: str, text: str, inline_keyboard=None, reply_to_message_id=None, chat_id=None):
    """Chart + card in ONE message when the card fits a photo caption (1024 chars); otherwise the photo goes first with a
    short caption and the full card follows as the normal (threaded, button-carrying) message. If Telegram refuses the
    photo (bad/expired file id, chat settings) the card is sent as a plain message instead - it is never lost."""
    text = str(text)
    cid = chat_id or ADMIN_CHAT_ID
    try:
        if len(text) <= 1000:
            payload = {"chat_id": cid, "photo": photo_id, "caption": text}
            if inline_keyboard is not None:
                payload["reply_markup"] = {"inline_keyboard": inline_keyboard}
            if reply_to_message_id:
                payload["reply_to_message_id"] = reply_to_message_id
                payload["allow_sending_without_reply"] = True
            body = telegram_call("sendPhoto", payload)
            return body.get("result", {}).get("message_id")
        head = text.split("\n", 1)[0][:200]
        payload = {"chat_id": cid, "photo": photo_id, "caption": head}
        if reply_to_message_id:
            payload["reply_to_message_id"] = reply_to_message_id
            payload["allow_sending_without_reply"] = True
        telegram_call("sendPhoto", payload)
    except Exception as e:
        status = getattr(getattr(e, "response", None), "status_code", None)
        if status not in (400, None) and not isinstance(e, RuntimeError):
            raise                                   # transient (network/5xx/429): let the caller retry the whole message
        log.warning("sendPhoto failed (%s); sending the card as text only", e)
    return send_message(text, inline_keyboard=inline_keyboard, chat_id=chat_id, reply_to_message_id=reply_to_message_id)


EXPORTS_DIR = Path("exports")


def send_document_message(doc_path: str, doc_name: str, text: str, queued_ts=None, inline_keyboard=None, chat_id=None,
                          reply_to_message_id=None):
    """Send an exported file (the executor commits it under exports/ BEFORE queueing the outbox line). Returns the message
    id. If the file is not here (yet / any more) the person gets a short text instead of silence; transient Telegram
    errors raise so the outbox line is retried. The file is removed after delivery (the next push commits the deletion)."""
    cid = chat_id or ADMIN_CHAT_ID
    p = Path(doc_path)
    try:
        p.resolve().relative_to(EXPORTS_DIR.resolve())          # only files inside exports/ may ever be sent
    except Exception:
        log.error("refusing to send a document outside exports/: %s", doc_path)
        return send_message("⚠️ The export file was invalid. Request it again.", inline_keyboard=inline_keyboard, chat_id=cid)
    if not p.is_file():
        pull_latest()                                            # the file may have been pushed a moment ago
    if not p.is_file():
        try:
            fresh = (time.time() - float(queued_ts)) < 150
        except (TypeError, ValueError):
            fresh = False
        if fresh:
            raise RuntimeError("export file not synced yet; will retry")      # transient: the outbox line is retried
        return send_message("⚠️ The export file is not ready yet or was deleted; tap “📥 Download Excel” again.",
                            inline_keyboard=inline_keyboard, chat_id=cid)
    data = {"chat_id": cid, "caption": str(text)[:1000]}
    if inline_keyboard is not None:
        data["reply_markup"] = json.dumps({"inline_keyboard": inline_keyboard}, ensure_ascii=False)
    with p.open("rb") as fh:
        r = requests.post(API + "/sendDocument", data=data, files={"document": (doc_name or p.name, fh)}, timeout=120)
    r.raise_for_status()
    body = r.json()
    if not body.get("ok"):
        raise RuntimeError(f"Telegram API error: {body}")
    try:
        p.unlink()
    except OSError:
        pass
    return body.get("result", {}).get("message_id")


def delete_message(chat_id: str, message_id) -> None:
    """Best-effort: remove a subscriber's message that contained their raw API key/secret from
    their own chat right after it was encrypted. If Telegram refuses, nothing else is affected
    (the key was already encrypted and never logged)."""
    try:
        telegram_call("deleteMessage", {"chat_id": chat_id, "message_id": message_id})
    except Exception:
        log.warning("could not delete a sensitive message (chat %s)", chat_id)


def clear_reply_keyboard(chat_id: str) -> bool:
    """Silently remove the old persistent bottom keyboard from a subscriber's chat (send an invisible-ish message that
    removes it, then delete that message). Returns True when Telegram accepted it."""
    try:
        mid = send_message("…", remove_keyboard=True, chat_id=chat_id, silent=True)
        if mid:
            delete_message(str(chat_id), mid)
        return True
    except Exception:
        log.warning("could not clear the bottom keyboard for chat %s", chat_id)
        return False


def copy_message(to_chat_id: str, from_chat_id: str, message_id) -> None:
    try:
        telegram_call("copyMessage", {"chat_id": to_chat_id, "from_chat_id": from_chat_id, "message_id": message_id})
    except Exception:
        log.warning("could not copy message %s to admin", message_id)


def answer_callback(callback_id: str, text: str = "") -> None:
    try:
        payload = {"callback_query_id": callback_id}
        if text:
            payload["text"] = text[:190]
        telegram_call("answerCallbackQuery", payload)
    except Exception:
        pass


def setup_bot_commands() -> None:
    try:
        telegram_call("setMyCommands", {"commands": USER_BOT_COMMANDS})
        telegram_call("setMyCommands", {"commands": BOT_COMMANDS,
                                        "scope": {"type": "chat", "chat_id": int(ADMIN_CHAT_ID)}})
    except Exception:
        log.exception("Could not configure Telegram commands")


# --------------------------------------------------------------------------- keyboards
# No persistent bottom keyboard anymore. The two tables below only keep an OLD keyboard working for the moment until
# Telegram removes it from the chat (a tap on it still arrives as plain text).
USER_KB_TEXT = {"📋 My menu": "/menu", "📈 Open trades": "/mytrades", "📜 History": "/myhistory",
                "📊 Profit and loss": "/mypnl", "⚙️ Settings": "/mysettings"}


ADMIN_KB_TEXT = {"📈 Open trades": "/positions", "📊 System status": "/status", "📜 History": "/history",
                 "📊 Profit and loss": "/pnl", "👥 Users": "/listusers"}


def B(text: str, data: str) -> dict:
    return {"text": text, "callback_data": data}


def inline_main_menu():
    return [
        [B("📈 Open trades", "cmd:/positions"), B("💰 Balance", "cmd:/balance"), B("📊 Status", "cmd:/status")],
        [B("🔔 Turn signals on", "cmd:/resume"), B("🔕 Turn signals off", "cmd:/pause")],
        [B("📊 Reports", "m:report"), B("⚙️ Trade settings", "m:settings")],
        [B("📨 Signals and entries", "m:signals"), B("🛡 Maintenance and tools", "m:tools")],
        [B("👥 Users", "m:users"), B("💳 Sales and subscriptions", "m:sales")],
        [B("🎁 Growth and gifts", "m:growth"), B("📢 Broadcast message", "ask:broadcast")],
    ]


_BACK = [B("⬅️ Main panel", "menu")]
ADMIN_SUBMENUS = {
    "report": ("📊 Reports", "See the system status, trades and results here.", [
        [B("📊 System status", "cmd:/status"), B("💰 Balance", "cmd:/balance")],
        [B("📈 Open trades", "cmd:/positions"), B("📜 History", "cmd:/history")],
        [B("📊 Profit and loss", "cmd:/pnl"), B("📥 Download trades Excel", "cmd:/export")],
        [B("🧾 Logs", "cmd:/logs")],
        [B("🧪 API connection test", "cmd:/test_api"), B("👥 User list", "cmd:/listusers")]]),
    "settings": ("⚙️ Trade settings", "Risk and limits of new signals and turning signals on/off. Each button has ready options and a custom number.", [
        [B("🎯 Risk per trade", "risk_menu"), B("💵 Collateral cap", "collateral_menu")],
        [B("🔢 Maximum trades", "maxtrades_menu"), B("📈 Leverage", "leverage_menu")],
        [B("🛡 Safe stop-loss margin", "cmd:/stopbuffer"), B("🤖 Automatic exit", "cmd:/autoexit")],
        [B("🔔 Turn signals on", "cmd:/resume"), B("🔕 Turn signals off", "cmd:/pause")],
        [B("✏️ Bulk edit of committed amount", "cmd:/colall"), B("❌ Close all trades", "cmd:/closeall")]]),
    "signals": ("📨 Signals and entries", "Write/forward the signal right here. From here manage pending entries and trades.", [
        [B("➕ Step-by-step signal", "ask:newsig")],
        [B("📖 Signal sending guide", "cmd:/signalhelp"), B("⏳ Pending entries", "cmd:/pendingentries")],
        [B("📈 Open trades", "cmd:/positions"), B("🛡 Protection check", "cmd:/protection")],
        [B("🛡 Safe stop-loss margin", "cmd:/stopbuffer"), B("🤖 Automatic exit", "cmd:/autoexit")],
        [B("❌ Close all trades", "cmd:/closeall")]]),
    "tools": ("🛡 Maintenance and tools", "Health check, synchronization and recovery. If you see anything irregular start here.", [
        [B("🛡 Protection check", "cmd:/protection"), B("🔄 Synchronize", "cmd:/reconcile")],
        [B("♻️ Recovery", "cmd:/recover"), B("🧪 API test", "cmd:/test_api")],
        [B("🧾 Logs", "cmd:/logs"), B("📊 System status", "cmd:/status")]]),
    "users": ("👥 Users", "Add, extend, limit and message users. Tapping any user in the list opens their full panel.", [
        [B("👥 User list", "cmd:/listusers"), B("➕ Add user", "ask:adduser")],
        [B("💳 Pending payments", "cmd:/pendingpayments"), B("🎁 Free subscription", "cmd:/trialdays")],
        [B("🎁 Invite friends", "cmd:/refreward"), B("📢 Broadcast message", "ask:broadcast")]]),
    "sales": ("💳 Sales and subscriptions", "Plans, payment methods, discount codes and free subscription.", [
        [B("💰 Plans and wallet", "cmd:/listprices"), B("💳 Pending payments", "cmd:/pendingpayments")],
        [B("➕ USDT plan", "ask:priceusdt")],
        [B("💵 USDT address", "ask:setusdt")],
        [B("🎟 Discount codes", "cmd:/discounts"), B("🆕 Create discount code", "ask:newdiscount")],
        [B("🎁 Free subscription", "cmd:/trialdays"), B("🎁 Invite friends", "cmd:/refreward")]]),
    "growth": ("🎁 Growth and gifts", "Tools that attract and retain new users.", [
        [B("🎁 Free trial subscription", "cmd:/trialdays"), B("🎁 Invite friends", "cmd:/refreward")],
        [B("🎟 Discount codes", "cmd:/discounts"), B("🆕 Create discount code", "ask:newdiscount")],
        [B("📢 Broadcast message", "ask:broadcast"), B("👥 User list", "cmd:/listusers")]]),
}


def submenu(name: str):
    title, hint, rows = ADMIN_SUBMENUS[name]
    return f"{title}\n━━━━━━━━━━━━━━\n{hint}", rows + [_BACK]


ADMIN_MENU_TEXT = ("🤖 TRADE IS COOL admin panel\n━━━━━━━━━━━━━━\n"
                   "Everything is done with buttons and organized by task; wherever a number is needed the bot asks for it.\n"
                   "📨 To execute a signal, send its text right here or forward it.\n"
                   "Under every bot message there are also the buttons of that section.")


def send_menu(first: bool = False) -> None:
    send_message(ADMIN_MENU_TEXT, inline_keyboard=inline_main_menu())


ADMIN_PRESETS = {
    "risk_menu": ("🎯 Risk per trade (USDT)", "/risk", ["0.25", "0.5", "1", "2", "5", "10"], "arisk"),
    "collateral_menu": ("💵 Collateral cap per trade (USDT)", "/collateral", ["1", "1.25", "1.5", "2", "5", "10", "25"], "acol"),
    "maxtrades_menu": ("🔢 Maximum simultaneous trades", "/maxtrades", ["3", "5", "10", "15", "20"], "amax"),
    "leverage_menu": ("📈 Leverage", "/leverage", ["3", "5", "10", "15", "20"], "alev"),
}


def preset_menu(key: str):
    title, cmd, vals, ask = ADMIN_PRESETS[key]
    btns = [B(v + ("x" if cmd == "/leverage" else ""), f"cmd:{cmd} {v}") for v in vals]
    rows = [btns[i:i + 3] for i in range(0, len(btns), 3)]
    rows.append([B("✏️ Custom number", f"ask:{ask}")])
    rows.append([B("📋 Menu", "menu")])
    return f"{title}\n━━━━━━━━━━━━━━\nTap one or enter a custom number:", rows


def users_menu():
    return ("👥 User and subscription management\n━━━━━━━━━━━━━━\nEverything is done from here with buttons.",
            [[B("👥 User list", "cmd:/listusers"), B("➕ Add user", "ask:adduser")],
             [B("💳 Pending payments", "cmd:/pendingpayments"), B("💰 Plans and wallet", "cmd:/listprices")],
             [B("🎟 Discount codes", "cmd:/discounts"), B("📢 Broadcast message", "ask:broadcast")],
             [B("🤖 TICB link", "cmd:/ticb")],
             [B("📋 Menu", "menu")]])


# --------------------------------------------------------------------------- command relay
# --------------------------------------------------------------------------- "working on it" indicator
# Telegram's own button toast ("sent...") disappears after a few seconds, long before a slow answer
# arrives, so people think the bot is dead. While a request is waiting for its answer we therefore keep
# TWO signals alive in that chat: the "typing..." status under the bot's name (re-sent every ~4 s, because
# Telegram clears it after 5 s) and one small "working on it" message that is deleted the moment the
# answer is delivered (relay_outbox) - or turned into a short note if the answer takes too long.
PENDING_TTL_SECONDS = int(os.environ.get("PENDING_TTL_SECONDS", "90"))
PENDING_TEXT = "⏳ Working… please wait a few moments"
PENDING_LATE_TEXT = "⌛ The reply is slower than usual. If nothing comes, tap the button once more."
_typing_ts: dict = {}          # chat_id -> last time we sent the typing status (not persisted: avoids git churn)


def send_chat_action(chat_id: str) -> None:
    try:
        telegram_call("sendChatAction", {"chat_id": chat_id, "action": "typing"})
    except Exception:
        pass


def mark_pending(chat_id: str) -> None:
    """A command was just relayed for this chat: show that work is in progress until the reply arrives."""
    st = STATE_REF.get("state")
    if st is None:
        return
    pend = st.setdefault("pending", {})
    now = time.time()
    chat_id = str(chat_id)
    rec = pend.get(chat_id)
    if rec and now - float(rec.get("ts", 0)) < PENDING_TTL_SECONDS:
        rec["ts"] = now                    # a second tap while waiting: keep the one existing indicator
    else:
        mid = None
        try:
            mid = send_message(PENDING_TEXT, chat_id=chat_id, silent=True)
        except Exception:
            log.warning("could not send the working-on-it message to chat %s", chat_id)
        pend[chat_id] = {"ts": now, "mid": mid}
    send_chat_action(chat_id)
    _typing_ts[chat_id] = now


def clear_pending(chat_id) -> None:
    """The answer for this chat was delivered: remove the indicator."""
    st = STATE_REF.get("state")
    if st is None:
        return
    rec = (st.get("pending") or {}).pop(str(chat_id), None)
    _typing_ts.pop(str(chat_id), None)
    if rec and rec.get("mid"):
        delete_message(str(chat_id), rec["mid"])


def tick_pending(state: dict) -> bool:
    """Called every loop: keep 'typing...' alive and expire indicators whose answer never came."""
    pend = state.get("pending") or {}
    if not pend:
        return False
    now = time.time()
    changed = False
    for chat_id, rec in list(pend.items()):
        if now - float(rec.get("ts", 0)) > PENDING_TTL_SECONDS:
            pend.pop(chat_id, None)
            _typing_ts.pop(chat_id, None)
            changed = True
            if rec.get("mid"):
                try:
                    telegram_call("editMessageText", {"chat_id": chat_id, "message_id": rec["mid"], "text": PENDING_LATE_TEXT})
                except Exception:
                    delete_message(chat_id, rec["mid"])
            continue
        if now - _typing_ts.get(chat_id, 0) >= 4.0:
            send_chat_action(chat_id)
            _typing_ts[chat_id] = now
    return changed


# Heuristic only (the executor re-validates everything with its own strict parser, fwd_signal.py): is this admin
# message probably a trading signal - a stop-loss word plus an entry/target word plus a number?
_SIG_STOP = re.compile(r"stop\s*[-_]?\s*loss|\bstoploss\b|\bstop\b|\bsl\b|حد\s*ضرر|حدضرر|استاپ", re.IGNORECASE)
_SIG_ENTRY_TP = re.compile(r"\bentry\b|\benter\b|\btarget|\btp\s*\d?|\btp\b|\bt\s*\d\b|take\s*[-_]?\s*profit|\blimit\b|\bmarket\b|\bcmp\b|ورود|تارگت|اهداف|هدف|حد\s*سود|تی\s*پی|بازار|لیمیت"
                          r"|\b(?:buy|sell|long|short)\b|خرید|فروش|لانگ|شورت", re.IGNORECASE)


def looks_like_signal(text: str) -> bool:
    t = (text or "").translate(_FA_DIGITS)
    return bool(re.search(r"\d", t)) and bool(_SIG_STOP.search(t)) and bool(_SIG_ENTRY_TP.search(t))


# Why some buttons seemed to act twice: the answer takes a few seconds, so people tap again, and every tap used
# to become its own command. Two protections: (1) the exact same command from the same chat within a few seconds
# is dropped (a deliberate repeat after the answer arrived still works), (2) the same Telegram update is never
# turned into two commands even if a run is restarted.
DEBOUNCE_SECONDS = float(os.environ.get("COMMAND_DEBOUNCE_SECONDS", "4"))
_recent_cmds: dict = {}


def is_duplicate_tap(chat_id, command: str) -> bool:
    now = time.time()
    for k in [k for k, ts in _recent_cmds.items() if now - ts > 60]:
        _recent_cmds.pop(k, None)
    k = (str(chat_id), " ".join(str(command).split()))
    last = _recent_cmds.get(k)
    _recent_cmds[k] = now
    return last is not None and now - last < DEBOUNCE_SECONDS


def _command_already_queued(command_id: str) -> bool:
    try:
        if not COMMANDS.exists():
            return False
        needle = f'"command_id": "{command_id}"'
        with COMMANDS.open("r", encoding="utf-8") as f:
            return any(needle in line for line in f)
    except Exception:
        return False


def append_command(update_id: int, command: str, chat_id: str | None = None, meta: dict | None = None,
                   suffix: str = "") -> bool:
    """Queue one command for the executor. Returns False when it was dropped as a duplicate."""
    if is_duplicate_tap(chat_id if chat_id is not None else ADMIN_CHAT_ID, command):
        log.info("dropped duplicate tap: %s", command[:60])
        return False
    if _command_already_queued(f"tg-{update_id}{suffix}"):
        log.info("dropped already-queued update %s", update_id)
        return False
    payload = {
        "command_id": f"tg-{update_id}{suffix}",
        "update_id": update_id,
        "ts": time.time(),
        "command": command,
    }
    if chat_id is not None:
        # Presence of this field is what executor.py treats as "non-admin caller" (see caller_chat_id
        # there) - never set it for an admin command, and never omit it for a self-service one.
        payload["chat_id"] = str(chat_id)
        if meta:
            payload["meta"] = meta
    append_lines(COMMANDS, [json.dumps(payload, ensure_ascii=False)])
    return True


def encrypt_for_vault(plaintext: str) -> str:
    if not USER_VAULT_MASTER_KEY:
        raise RuntimeError("USER_VAULT_MASTER_KEY is not set")
    return Fernet(USER_VAULT_MASTER_KEY.encode()).encrypt(plaintext.strip().encode()).decode()


_user_hits: dict = {}
USER_RATE_WINDOW_SECONDS = 600
USER_RATE_MAX = 40


def user_rate_limited(chat_id: str) -> bool:
    """Any stranger can message a public bot. Every accepted message becomes a line in a public repo
    and triggers a reply, so one chat is limited to USER_RATE_MAX messages per window; the rest are
    silently dropped. The admin chat is never limited."""
    now = time.time()
    hits = [t for t in _user_hits.get(chat_id, []) if now - t < USER_RATE_WINDOW_SECONDS]
    if len(hits) >= USER_RATE_MAX:
        _user_hits[chat_id] = hits
        return True
    hits.append(now)
    _user_hits[chat_id] = hits
    return False


# --------------------------------------------------------------------------- wizard (button-driven prompts)
WIZARD_TTL_SECONDS = 20 * 60
_FA_DIGITS = str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩٫٬،", "01234567890123456789.,,")
_wizard: dict = {}          # chat_id -> {"prompt": str, "arg": str, "step": int, "data": {...}, "ts": float}


def _norm_number(text: str):
    t = text.strip().translate(_FA_DIGITS).replace(",", "").replace(" ", "")
    if not t or len(t) > 20:
        return None
    try:
        v = float(t)
    except ValueError:
        return None
    if v != v or v in (float("inf"), float("-inf")):
        return None
    return t


def _q(text: str) -> str:
    return text


# Each prompt: list of steps; a step = (question, kind). kinds: num | int | text | secret | days
# `build(is_admin, arg, answers)` -> command string (or None when handled specially).
PROMPTS = {
    # ---- subscriber ----
    "apikey": {"admin": False, "steps": [
        ("🔑 Step 1 of 2 — Access Key (API Key)\n\nHow to create the key: Toobit → profile icon → API Management → + New API.\n"
         "Turn on only “Read” and “Futures trading”; withdrawal must be OFF and do not set any trusted-IP restriction (the key lasts 90 days).\n\nCopy the Access Key and send it right here.\n"
         "🔒 Your message is encrypted immediately and deleted from the chat.", "secret"),
        ("✅ Access Key received.\n\n🔑 Step 2 of 2 — Secret Key\n\nNow send the Secret Key.\n"
         "🔒 This message is also encrypted and deleted immediately.", "secret")]},
    "receipt": {"admin": False, "steps": [
        ("🧾 Send the tracking code (or transaction hash) of the payment.\nIf you have the receipt as a photo you can send that photo too.", "text")]},
    "support": {"admin": False, "steps": [("🆘 Write your message for support:", "text")]},
    "discount": {"admin": False, "steps": [("🎟 Send the discount code (for example EID20):", "text")]},
    "newsig": {"both": True, "steps": [("x", "text")]},          # dynamic step-by-step form, see start_newsig()
    "setrisk": {"admin": False, "steps": [("🎯 How many USDT should the risk per trade be? (number only, for example 1)", "num")]},
    "setcol": {"admin": False, "steps": [("💵 How many USDT should the collateral cap per trade be? (number only)", "num")]},
    "setlev": {"admin": False, "steps": [("📈 How many times the leverage? (number only, for example 20)", "num")]},
    "setmax": {"admin": False, "steps": [("🔢 How many simultaneous trades at most? (whole number)", "int")]},
    "setdaily": {"admin": False, "steps": [("🛑 Daily loss cap in USDT? (0 = off)", "num")]},
    "liqadd": {"admin": False, "steps": [("➕ How many USDT should be added to this trade's collateral? (number only, for example 5)", "num")]},
    "recamt": {"admin": False, "steps": [("🧮 How many USDT do you have in the Futures account or plan to transfer? (number only, for example 100)", "num")]},
    "reqcap": {"admin": False, "steps": [("📨 Send the value you want (number only). The request is sent to the admin:", "num")]},
    # ---- shared (subscriber or admin) ----
    "colallpct": {"both": True, "steps": [("✏️ By what percent should the collateral of all trades increase? (a number between 1 and 100)", "num")]},
    "colallto": {"both": True, "steps": [("🎯 The collateral of each trade should become how many USDT? (number only; only increases are done)", "num")]},
    # ---- admin ----
    "adduser": {"admin": True, "steps": [("➕ Send the user's numeric Telegram id:", "int"),
                                         ("📅 How many days of gift subscription should I give? (number only)", "num")]},
    "extend": {"admin": True, "steps": [("📅 How many days to extend? (number only)", "num")]},
    "userrisk": {"admin": True, "steps": [("🎯 Risk ceiling per trade (USDT):", "num"), ("💵 Collateral ceiling per trade (USDT):", "num"),
                                          ("📈 Leverage ceiling:", "num"), ("🔢 Simultaneous trades ceiling:", "int")]},
    "msguser": {"admin": True, "steps": [("✉️ The message text for this user:", "text")]},
    "reply": {"admin": True, "steps": [("✍️ The reply text to the user:", "text")]},
    "broadcast": {"admin": True, "steps": [("📢 The broadcast text (for all non-blocked users):", "text")]},
    "rejectreason": {"admin": True, "steps": [("✍️ Write the reason for rejecting the payment (it is told to the user):", "text")]},
    "newdiscount": {"admin": True, "steps": [
        ("🎟 Send the discount code name (English letters/digits only, for example EID20):", "text"),
        ("% How many percent discount? (a number between 1 and 99)", "num"),
        ("📅 Which subscriptions should it apply to?\nSend the durations separated by commas, for example 30,90 — or write all for all:", "text"),
        ("🔢 How many people can use it at most? (0 = unlimited)", "int"),
        ("⏳ How many days should it be valid? (0 = no expiry)", "num")]},
    "pricetoman": {"admin": True, "steps": [("📅 Duration (days):", "int"), ("💳 Price in Toman (number only):", "num")]},
    "priceusdt": {"admin": True, "steps": [("📅 Duration (days):", "int"), ("💵 Price in USDT (number only):", "num")]},
    "setcard": {"admin": True, "steps": [("💳 Send the card number:", "text"), ("👤 Card holder name:", "text")]},
    "setusdt": {"admin": True, "steps": [("💵 USDT wallet address:", "text"), ("🌐 Network name (for example TRC20):", "text")]},
    "atrial": {"admin": True, "steps": [("🎁 How many days should the free trial subscription be? (0 = off)", "num")]},
    "arefd": {"admin": True, "steps": [("🎁 How many days should the inviter's gift be? (0 = off)", "num")]},
    "arefi": {"admin": True, "steps": [("🎁 How many days should the invited friend's gift be? (0 = no gift)", "num")]},
    "astopbuf": {"admin": True, "steps": [("🛡 Safe stop-loss margin as what percent of the price? (0 to 1; for example 0.1)", "num")]},
    "trialuser": {"admin": True, "steps": [("🎁 How many days should this user's free subscription be? (0 = no free subscription)", "num")]},
    "arisk": {"admin": True, "steps": [("🎯 Risk per trade (USDT)?", "num")]},
    "acol": {"admin": True, "steps": [("💵 Collateral cap per trade (USDT)?", "num")]},
    "amax": {"admin": True, "steps": [("🔢 Maximum simultaneous trades?", "int")]},
    "alev": {"admin": True, "steps": [("📈 Leverage?", "num")]},
    "ucolallpct": {"admin": True, "steps": [("✏️ By what percent should the collateral of all this user's trades increase? (1 to 100)", "num")]},
    "ucolallto": {"admin": True, "steps": [("🎯 The collateral of each trade should become how many USDT?", "num")]},
}
_USER_FIELD_OF_ASK = {"setrisk": "risk", "setcol": "col", "setlev": "lev", "setmax": "max", "setdaily": "daily"}


def _build_command(name: str, arg: str, answers: list, is_admin: bool):
    a = answers
    if name == "receipt":
        return f"/paid {arg} {a[0]}"
    if name == "support":
        return f"/support {a[0]}"
    if name in _USER_FIELD_OF_ASK:
        return f"/myset {_USER_FIELD_OF_ASK[name]} {a[0]}"
    if name == "reqcap":
        return f"/reqcap {arg} {a[0]}"
    if name == "recamt":
        return f"/rec {a[0]}"
    if name == "liqadd":
        return f"/myliqadd {arg} {a[0]}"
    if name in ("colallpct", "colallto"):
        mode = "pct" if name == "colallpct" else "to"
        return f"/colall {mode} {a[0]}" if is_admin else f"/mycolall {mode} {a[0]}"
    if name == "adduser":
        return f"/adduser {int(float(a[0]))} {a[1]}"
    if name == "extend":
        return f"/extenduser {arg} {a[0]}"
    if name == "userrisk":
        return f"/setuserrisk {arg} {a[0]} {a[1]} {a[2]} {int(float(a[3]))}"
    if name in ("msguser", "reply"):
        return f"/msguser {arg} {a[0]}"
    if name == "discount":
        code = "".join(str(a[0]).split())
        return f"/usediscount {code}" if code else None
    if name == "newdiscount":
        code = "".join(str(a[0]).split())
        plans = "".join(str(a[2]).split()) or "all"
        if not code or not all(ch.isdigit() or ch == "," for ch in plans.replace("all", "").replace("All", "")):
            return None
        return f"/newdiscount {code} {a[1]} {plans} {int(float(a[3]))} {a[4]}"
    if name == "broadcast":
        return f"/broadcast {a[0]}"
    if name == "rejectreason":
        return f"/rejectpayment {arg} {a[0]}"
    if name == "pricetoman":
        return f"/setpricetoman {int(float(a[0]))} {a[1]}"
    if name == "priceusdt":
        return f"/setpriceusdt {int(float(a[0]))} {a[1]}"
    if name == "setcard":
        return f"/setcard {a[0].replace(' ', '')} {a[1]}"
    if name == "setusdt":
        return f"/setusdt {a[0].replace(' ', '')} {a[1].replace(' ', '') or 'TRC20'}"
    if name == "atrial":
        return f"/trialdays {a[0]}"
    if name == "arefd":
        return f"/refreward {a[0]}"
    if name == "arefi":
        return f"/refreward - {a[0]}"
    if name == "astopbuf":
        return f"/stopbuffer {a[0]}"
    if name == "trialuser":
        return f"/trialuser {arg} {a[0]}"
    if name == "arisk":
        return f"/risk {a[0]}"
    if name == "acol":
        return f"/collateral {a[0]}"
    if name == "amax":
        return f"/maxtrades {int(float(a[0]))}"
    if name == "alev":
        return f"/leverage {a[0]}"
    if name in ("ucolallpct", "ucolallto"):
        return f"/usercolall {arg} {'pct' if name == 'ucolallpct' else 'to'} {a[0]}"
    return None


def _cancel_row(is_admin: bool):
    return [[B("❌ Cancel", "wiz:cancel")]]


def _ask_question(chat_id: str, name: str, arg: str, step: int, prefix: str = "") -> None:
    q, _kind = PROMPTS[name]["steps"][step]
    extra = ""
    if name == "receipt":
        extra = f"\n\n(payment id: {arg})"
    send_message(prefix + q + extra, inline_keyboard=_cancel_row(chat_id == ADMIN_CHAT_ID), chat_id=chat_id)


def start_wizard(chat_id: str, data: str, is_admin: bool) -> bool:
    """`data` looks like 'ask:<prompt>[:arg]'. Returns True if a prompt was started."""
    bits = data.split(":", 2)
    name = bits[1] if len(bits) > 1 else ""
    arg = bits[2] if len(bits) > 2 else ""
    spec = PROMPTS.get(name)
    if not spec:
        return False
    if name == "newsig":
        return start_newsig(chat_id)
    if is_admin and spec.get("admin") is False:
        pass                                   # the admin may also use user prompts harmlessly
    if not is_admin and spec.get("admin") is True:
        return False                           # a subscriber can never start an admin prompt
    _wizard[chat_id] = {"prompt": name, "arg": arg, "step": 0, "answers": [], "ts": time.time()}
    _ask_question(chat_id, name, arg, 0)
    return True


def _persist_wizard(state: dict) -> None:
    now = time.time()
    keep = {k: v for k, v in _wizard.items() if now - v.get("ts", 0) < WIZARD_TTL_SECONDS}
    _wizard.clear()
    _wizard.update(keep)
    state["wizard"] = keep


def _load_wizard(state: dict) -> None:
    _wizard.clear()
    now = time.time()
    for k, v in (state.get("wizard") or {}).items():
        if isinstance(v, dict) and now - float(v.get("ts", 0)) < WIZARD_TTL_SECONDS:
            _wizard[str(k)] = v


def handle_wizard_input(update: dict, chat_id: str, text: str, is_admin: bool, meta: dict) -> bool:
    """Feed a free-text answer into the active prompt. Returns True if consumed."""
    w = _wizard.get(chat_id)
    if not w:
        return False
    if time.time() - float(w.get("ts", 0)) > WIZARD_TTL_SECONDS:
        _wizard.pop(chat_id, None)
        return False
    if w.get("prompt") == "newsig":
        return _ns_input(update, chat_id, text, is_admin, meta)
    name, arg, step = w["prompt"], w["arg"], int(w["step"])
    spec = PROMPTS.get(name)
    if not spec:
        _wizard.pop(chat_id, None)
        return False
    _q_text, kind = spec["steps"][step]
    msg = update.get("message") or {}
    mid = msg.get("message_id")
    uid = int(update["update_id"])

    # a receipt may be a photo
    if name == "receipt" and (msg.get("photo") or msg.get("document")) and not is_admin:
        copy_message(ADMIN_CHAT_ID, chat_id, mid)
        text = (msg.get("caption") or "").strip() or "📷 Receipt image (sent to the admin in the bot chat)"

    if kind == "secret":
        # Sensitive: remove it from the chat right away, whatever happens next.
        if mid:
            delete_message(chat_id, mid)
        parts = text.split()
        if name == "apikey" and step == 0 and len(parts) == 2 and all(16 <= len(x) <= 300 for x in parts):
            # both keys in one message: accept and finish
            try:
                enc_pub, enc_priv = encrypt_for_vault(parts[0]), encrypt_for_vault(parts[1])
            except RuntimeError:
                _wizard.pop(chat_id, None)
                log.error("USER_VAULT_MASTER_KEY missing - refusing to relay a key at all (never relay plaintext)")
                send_message("⚠️ The key connection service is temporarily unavailable; try again a little later or message support.",
                             chat_id=chat_id, inline_keyboard=[[B("🆘 Support", "ask:support")]])
                return True
            append_command(uid, f"/connect_enc {enc_pub} {enc_priv}", chat_id=chat_id, meta=meta)
            _wizard.pop(chat_id, None)
            send_message("🔐 The keys were encrypted and sent for verification (the message containing the key was deleted from the chat). Wait a few moments...", chat_id=chat_id)
            return True
        if len(parts) != 1 or not (16 <= len(parts[0]) <= 300):
            send_message("⚠️ The key does not look complete. Copy and send only that single key string (no spaces and no extra text).",
                         inline_keyboard=_cancel_row(False), chat_id=chat_id)
            return True
        try:
            enc = encrypt_for_vault(parts[0])
        except RuntimeError:
            _wizard.pop(chat_id, None)
            log.error("USER_VAULT_MASTER_KEY missing - refusing to relay a key at all (never relay plaintext)")
            send_message("⚠️ The key connection service is temporarily unavailable; try again a little later or message support.",
                         chat_id=chat_id, inline_keyboard=[[B("🆘 Support", "ask:support")]])
            return True
        w["answers"].append(enc)
        answer = enc
    elif kind in ("num", "int"):
        n = _norm_number(text)
        if n is None or (kind == "int" and float(n) != int(float(n))):
            send_message("⚠️ Please send only one number" + (" (whole number)" if kind == "int" else "") + "; for example 5",
                         inline_keyboard=_cancel_row(is_admin), chat_id=chat_id)
            return True
        answer = n
        w["answers"].append(answer)
    else:
        t = text.strip()
        if not t:
            send_message("⚠️ The text is empty; send it again.", inline_keyboard=_cancel_row(is_admin), chat_id=chat_id)
            return True
        answer = t[:1000]
        w["answers"].append(answer)

    w["ts"] = time.time()
    if step + 1 < len(spec["steps"]):
        w["step"] = step + 1
        _ask_question(chat_id, name, arg, step + 1)
        return True

    # last step: build the command
    answers = list(w["answers"])
    _wizard.pop(chat_id, None)
    if name == "apikey":
        append_command(uid, f"/connect_enc {answers[0]} {answers[1]}", chat_id=chat_id, meta=meta)
        send_message("🔐 Both keys were encrypted and sent for verification (the messages containing the keys were deleted from the chat; if not deleted, delete them yourself).\n"
                     "Wait a few moments while the connection is tested...", chat_id=chat_id)
        return True
    try:
        command = _build_command(name, arg, answers, is_admin)
    except (ValueError, IndexError):
        command = None
    if not command:
        send_message("⚠️ The input was not valid; start again from the menu.", chat_id=chat_id,
                     inline_keyboard=[[B("📋 Menu", "menu" if is_admin else "cmd:/menu")]])
        return True
    queued = append_command(uid, command) if is_admin else append_command(uid, command, chat_id=chat_id, meta=meta)
    if queued:
        mark_pending(chat_id)
    return True


# --------------------------------------------------------------------------- step-by-step signal form
# "➕ ثبت سیگنال گام‌به‌گام": asks coin, direction, entry type/price, stop, targets, profit share of each target and how the
# stop moves - with buttons wherever there is a fixed choice - and finally relays ONE ordinary signal text to the
# executor (the same /fwdsignal or /mysignal path a forwarded signal takes, so every safety check there applies).
_SPLITS = {1: [100], 2: [50, 50], 3: [40, 30, 30], 4: [30, 30, 20, 20], 5: [25, 25, 20, 15, 15], 6: [20, 20, 20, 15, 15, 10]}
_STOPMOVE_FA = {"fixed": "🔒 stays fixed", "entry": "1️⃣ after target 1 it moves to the entry point", "ladder": "🪜 laddered: with every target it moves to the entry / previous target"}
_STOPMOVE_WORD = {"fixed": "fixed", "entry": "breakeven", "ladder": "ladder"}
_NS_CHOICES = {
    "side": [("🟢 Long (buy)", "LONG"), ("🔴 Short (sell)", "SHORT")],
    "otype": [("⚡ Market — right now", "market"), ("🎯 Specific price (Limit)", "limit")],
    "split": [("⚖️ Automatic split", "auto"), ("✏️ I will write the percentages myself", "manual")],
    "stopmove": [("🔒 Keep it fixed", "fixed"), ("1️⃣ After target 1 move it to the entry", "entry"), ("🪜 Laddered (each target → the previous one)", "ladder")],
    "confirm": [("✅ Register and open", "go"), ("↩️ Start again", "again")],
}


def _ns_numbers(text: str) -> list:
    t = (text or "").translate(_FA_DIGITS)
    t = re.sub(r"(?<=\d),(?=\d{3}(?!\d))", "", t)                 # 60,000 -> 60000
    out = []
    for tok in re.split(r"[\s,;|]+", t):
        tok = tok.strip().rstrip("%")
        if not tok:
            continue
        try:
            v = float(tok)
        except ValueError:
            return []
        if v != v or v <= 0:
            return []
        out.append(tok)
    return out


def _ns_fmt(tok) -> str:
    return str(tok)


def _ns_next_field(d: dict):
    for f in ("sym", "side", "otype"):
        if f not in d:
            return f
    if d["otype"] == "limit" and "entry" not in d:
        return "entry"
    for f in ("stop", "targets"):
        if f not in d:
            return f
    n = len(d["targets"])
    if n > 1:
        if "split" not in d:
            return "split"
        if d["split"] == "manual" and "shares" not in d:
            return "shares"
        if "stopmove" not in d:
            return "stopmove"
    return "confirm" if "confirm" not in d else None


def _ns_shares_of(d: dict) -> list:
    n = len(d["targets"])
    return [float(x) for x in d["shares"]] if d.get("split") == "manual" else [float(x) for x in _SPLITS[n]]


def _ns_summary(d: dict) -> str:
    n = len(d["targets"])
    sh = _ns_shares_of(d)
    lines = ["📋 Summary of your signal", "━━━━━━━━━━━━━━",
             f"🪙 {d['sym']}/USDT — " + ("🟢 Long (buy)" if d["side"] == "LONG" else "🔴 Short (sell)"),
             ("⚡ Entry: market (right now at the market price)" if d["otype"] == "market" else f"🎯 Entry (Limit): {d['entry']}"),
             f"🛑 Stop-loss: {d['stop']}", "🎯 Targets and profit-saving percentage:"]
    for i, (t, w) in enumerate(zip(d["targets"], sh), 1):
        lines.append(f"   T{i}: {t} — {w:g}% of the size")
    lines.append("🔒 Stop-loss: " + _STOPMOVE_FA[d.get("stopmove", "fixed") if n > 1 else "fixed"])
    lines += ["", "When confirmed, the trade opens as quickly as possible with your own trade-management settings (risk, leverage and ceilings) "
                  "and its details are sent to you."]
    return "\n".join(lines)


def _ns_text(d: dict) -> str:
    n = len(d["targets"])
    lines = [f"Symbol: {d['sym']}USDT", d["side"], ("Entry: Market" if d["otype"] == "market" else f"Entry: {d['entry']}"),
             f"Stop: {d['stop']}"] + [f"Target {i}: {t}" for i, t in enumerate(d["targets"], 1)]
    if n > 1:
        if d.get("split") == "manual":
            lines.append("Shares: " + "/".join(f"{x:g}" for x in _ns_shares_of(d)))
        lines.append("Stop move: " + _STOPMOVE_WORD[d.get("stopmove", "fixed")])
    return "\n".join(lines)


def _ns_ask(chat_id: str, d: dict, prefix: str = "") -> None:
    f = _ns_next_field(d)
    cancel = [B("❌ Cancel", "wiz:cancel")]
    if f == "confirm":
        rows = [[B(lbl, "wz:" + val)] for lbl, val in _NS_CHOICES["confirm"]]
        send_message(prefix + _ns_summary(d), inline_keyboard=rows + [cancel], chat_id=chat_id)
        return
    if f in _NS_CHOICES:
        q = {"side": "🧭 What is the direction of the trade?", "otype": "⚙️ What is the entry type?\n• Market: enter right now at the market price.\n• Specific price: the order rests at the price you write.",
             "split": "💰 How should the profit-saving percentage at each target be?", "stopmove": "🔒 How should the stop-loss move after the targets are reached?"}[f]
        rows = [[B(lbl, "wz:" + val)] for lbl, val in _NS_CHOICES[f]]
        send_message(prefix + q, inline_keyboard=rows + [cancel], chat_id=chat_id)
        return
    n = len(d.get("targets", []))
    q = {"sym": "➕ Step-by-step signal registration\n\n🪙 Write the coin name (for example BTC or NEAR or Bitcoin):",
         "entry": "🎯 Write the entry price (number only):",
         "stop": "🛑 Write the stop-loss price (number only):",
         "targets": "🎯 Write the target prices (1 to 6 numbers; separated by space, comma or one number per line):",
         "shares": (f"✏️ Write the profit-saving percentage of each target in order ({n} numbers that add up to 100; for example "
                    + " ".join(str(x) for x in _SPLITS.get(n, [100])) + "):")}[f]
    send_message(prefix + q, inline_keyboard=[cancel], chat_id=chat_id)


def start_newsig(chat_id: str) -> bool:
    _wizard[chat_id] = {"prompt": "newsig", "arg": "", "step": 0, "answers": [], "data": {}, "ts": time.time()}
    _ns_ask(chat_id, {})
    return True


def _ns_accept(field: str, raw: str, d: dict):
    """-> (value, error). Everything is checked here so a wrong number is caught while the person is still typing."""
    raw = (raw or "").strip()
    if field in _NS_CHOICES:
        allowed = [v for _l, v in _NS_CHOICES[field]]
        return (raw, None) if raw in allowed else (None, "Please tap one of the buttons.")
    if field == "sym":
        t = raw.upper().replace("#", "").replace("$", "").replace(" ", "")
        t = re.sub(r"[/\-_]?(USDT|USD)$", "", t)
        if re.fullmatch(r"[A-Z0-9]{2,10}", t):
            return t, None
        if re.search(r"[آ-ی]", raw) and len(raw) <= 30:
            return raw, None                                    # a Persian coin name: the executor knows the common ones
        return None, "Write the coin name in English letters; for example BTC or NEAR."
    if field in ("entry", "stop"):
        n = _norm_number(raw)
        if n is None or float(n) <= 0:
            return None, "Write only a positive number; for example 4.67"
        if field == "stop" and d.get("otype") == "limit":
            e = float(d["entry"])
            if d["side"] == "LONG" and not float(n) < e:
                return None, "For a buy (Long) the stop-loss must be lower than the entry price."
            if d["side"] == "SHORT" and not float(n) > e:
                return None, "For a sell (Short) the stop-loss must be higher than the entry price."
        return n, None
    if field == "targets":
        toks = _ns_numbers(raw)
        if not toks or len(toks) > 6:
            return None, "Write between 1 and 6 numbers (target prices only)."
        vals = sorted(((float(x), x) for x in toks), reverse=(d["side"] == "SHORT"))
        if len({v for v, _x in vals}) != len(vals):
            return None, "The targets must not be duplicated."
        stop = float(d["stop"])
        if d["otype"] == "limit":
            ref = float(d["entry"])
            bad = [x for v, x in vals if (v >= ref if d["side"] == "SHORT" else v <= ref)]
            if bad:
                return None, ("For a sell (Short) the targets must be lower than the entry price." if d["side"] == "SHORT"
                              else "For a buy (Long) the targets must be higher than the entry price.")
        else:
            bad = [x for v, x in vals if (v >= stop if d["side"] == "SHORT" else v <= stop)]
            if bad:
                return None, "The targets must be on the profit side (lower in a Short and higher in a Long than the stop-loss)."
        return [x for _v, x in vals], None
    if field == "shares":
        toks = _ns_numbers(raw)
        n = len(d["targets"])
        if len(toks) != n:
            return None, f"Write exactly {n} numbers (one percentage for each target)."
        if abs(sum(float(x) for x in toks) - 100) > 0.5:
            return None, "The percentages must add up to 100."
        return toks, None
    return None, "Invalid input."


def _ns_input(update: dict, chat_id: str, raw: str, is_admin: bool, meta: dict) -> bool:
    w = _wizard.get(chat_id)
    if not w or w.get("prompt") != "newsig":
        return False
    d = w.setdefault("data", {})
    field = _ns_next_field(d)
    if field is None:
        _wizard.pop(chat_id, None)
        return True
    val, err = _ns_accept(field, raw, d)
    if err:
        send_message("⚠️ " + err, inline_keyboard=[[B("❌ Cancel", "wiz:cancel")]], chat_id=chat_id)
        return True
    w["ts"] = time.time()
    if field == "confirm":
        if val == "again":
            w["data"] = {}
            _ns_ask(chat_id, {})
            return True
        text = _ns_text(d)
        _wizard.pop(chat_id, None)
        payload = base64.b64encode(text.encode("utf-8")).decode("ascii")
        uid = int(update["update_id"])
        if is_admin:
            queued = append_command(uid, f"/fwdsignal b64:{payload}")
        else:
            queued = append_command(uid, f"/mysignal b64:{payload}", chat_id=chat_id, meta=meta)
        if queued:
            mark_pending(chat_id)
        send_message("⏳ Your signal was registered; checking it and opening the trade is in progress...", chat_id=chat_id)
        return True
    d[field] = val
    if field == "targets" and len(val) == 1:
        d["split"], d["stopmove"] = "auto", "fixed"
    _ns_ask(chat_id, d)
    return True


def handle_wizard_button(update: dict, chat_id: str, value: str, is_admin: bool, meta: dict) -> bool:
    """A 'wz:<value>' button tap of the step-by-step form."""
    w = _wizard.get(chat_id)
    if not w or w.get("prompt") != "newsig":
        send_message("⌛ This form expired; from the menu tap “➕ Step-by-step signal” again.", chat_id=chat_id,
                     inline_keyboard=[[B("📋 Menu", "menu" if is_admin else "cmd:/menu")]])
        return True
    return _ns_input(update, chat_id, value, is_admin, meta)



def _meta_of(frm: dict) -> dict:
    return {"first_name": str((frm or {}).get("first_name") or "")[:60], "username": str((frm or {}).get("username") or "")[:40]}


# --------------------------------------------------------------------------- messages
_FAQ_RULES = (
    # (help topic, keywords) - first match wins, so the most specific topics come first
    ("glossary", ("liquidation", "liquidated", "liquid", "meaning", "what does it mean", "what is")),
    ("trouble", ("not opened", "not executed", "not coming", "does not arrive", "not arriving", "not received", "does not reach", "error", "problem", "not working", "does not work",
                 "no answer", "no reply", "why", "not accepted", "cannot connect", "not connected")),
    ("start", ("Start", "how to connect", "api key", "api", "connection", "sign up", "signup", "no toobit account")),
    ("rec", ("budget", "how much to put", "how much to deposit", "profile", "suggestion", "low risk", "Low risk", "High risk", "high risk")),
    ("settings", ("Leverage", "risk", "collateral", "setting", "cap", "auto exit")),
    ("sub", ("Subscription", "renew", "payment", "card", "price", "plan", "discount", "invite", "referral", "gift", "free")),
    ("manage", ("trade", "position", "close", "closing", "target", "stop-loss", "profit", "loss", "history")),
    ("signal", ("signal",)),
    ("safe", ("withdraw", "safe", "security", "hack", "my money", "my funds")),
)


def faq_topic(text: str):
    """Map a free-text question from a subscriber to the help page that answers it (None = no idea)."""
    t = (text or "").translate({0x200c: " ", 0x200f: None, 0x200e: None}).replace("ي", "ی").replace("ك", "ک").lower()
    if len(t) < 3 or len(t) > 300:
        return None
    for topic, words in _FAQ_RULES:
        if any(w.lower() in t for w in words):
            return topic
    return None


def handle_self_service_message(update: dict, chat_id: str, text: str) -> bool:
    """Non-admin chat. Only SELF_SERVICE_COMMANDS (and wizard answers) ever reach commands.jsonl,
    always tagged with chat_id so executor.py knows this is not the admin (it enforces the same
    allow-list independently). Everything else is treated as a request for the menu."""
    msg = update.get("message") or {}
    if (msg.get("chat") or {}).get("type") != "private":
        return True                               # the bot only talks in private chats
    uid = int(update["update_id"])
    meta = _meta_of(msg.get("from") or {})
    parts = text.split()
    cmd = parts[0].lower().split("@")[0] if parts else ""
    if user_rate_limited(chat_id):
        return True

    # Leaving any prompt: a command or a reply-keyboard button always wins over a pending prompt.
    is_menu_text = text in USER_KB_TEXT or text == "🆘 Support"
    if cmd.startswith("/") or is_menu_text:
        _wizard.pop(chat_id, None)
    elif chat_id in _wizard:
        return handle_wizard_input(update, chat_id, text, False, meta)
    elif msg.get("photo") or msg.get("document"):
        send_message("📎 The file was not received. To send a payment receipt, tap “I have paid — send receipt” from the menu.",
                     chat_id=chat_id, inline_keyboard=[[B("📋 My menu", "cmd:/menu")]])
        return True

    if text == "🆘 Support":
        start_wizard(chat_id, "ask:support", False)
        return True
    if text in USER_KB_TEXT:
        if append_command(uid, USER_KB_TEXT[text], chat_id=chat_id, meta=meta):
            mark_pending(chat_id)
        return True

    if cmd == "/connect" and len(parts) == 3:               # old typed style still works
        try:
            enc_pub = encrypt_for_vault(parts[1])
            enc_priv = encrypt_for_vault(parts[2])
        except RuntimeError:
            log.error("USER_VAULT_MASTER_KEY missing - refusing to relay a /connect at all (never relay plaintext)")
            send_message("⚠️ The key connection service is temporarily unavailable; try again later.", chat_id=chat_id)
            return True
        append_command(uid, f"/connect_enc {enc_pub} {enc_priv}", chat_id=chat_id, meta=meta)
        mid = msg.get("message_id")
        if mid:
            delete_message(chat_id, mid)
        send_message("🔐 Your key was encrypted and sent for verification (the message containing the key was deleted). Wait a few moments...", chat_id=chat_id)
        return True

    if cmd in SELF_SERVICE_COMMANDS and cmd != "/connect_enc":
        if append_command(uid, text if cmd == parts[0].lower() else " ".join([cmd] + parts[1:]), chat_id=chat_id, meta=meta):
            mark_pending(chat_id)
        return True

    # A subscriber's own trading signal (free text, Persian/English, any layout): the executor parses it strictly and
    # runs it on THEIR account only, after checking subscription / key / terms / pause there.
    if not text.startswith("/") and looks_like_signal(text):
        import base64 as _b64
        payload = _b64.b64encode(text[:3500].encode("utf-8")).decode("ascii")
        if append_command(uid, f"/mysignal b64:{payload}", chat_id=chat_id, meta=meta):
            mark_pending(chat_id)
        return True

    # A typed question: answer it with the matching help page (no commands needed); anything else shows the menu.
    topic = faq_topic(text) if not text.startswith("/") else None
    if append_command(uid, f"/help {topic}" if topic else "/menu", chat_id=chat_id, meta=meta):
        mark_pending(chat_id)
    return True


def handle_message(update: dict) -> bool:
    msg = update.get("message") or {}
    chat = msg.get("chat", {})
    chat_id = str(chat.get("id"))
    text = (msg.get("text") or msg.get("caption") or "").strip()
    if chat_id != ADMIN_CHAT_ID:
        return handle_self_service_message(update, chat_id, text)

    uid = int(update["update_id"])
    cmd = text.split()[0].lower().split("@")[0] if text.split() else ""
    _is_fwd = any(k in msg for k in ("forward_origin", "forward_from_chat", "forward_from", "forward_date", "forward_sender_name"))
    if cmd.startswith("/") or text in ADMIN_KB_TEXT or text in ("📋 Menu", "menu", "menu"):
        _wizard.pop(chat_id, None)
    elif chat_id in _wizard and (_is_fwd or looks_like_signal(text)) and "\n" in text:
        _wizard.pop(chat_id, None)      # a forwarded/pasted signal must never be swallowed as the answer of a half-finished prompt
    elif chat_id in _wizard:
        return handle_wizard_input(update, chat_id, text, True, {})

    if cmd in ("/start", "/menu", "/help") or text in ("menu", "menu", "📋 Menu", "help"):
        send_menu()
        st_ref = STATE_REF.get("state")
        if st_ref is not None and not st_ref.get("admin_kb_cleared"):
            # The Toobit edition has no persistent bottom keyboard; remove the old one (if any) from the admin chat, once.
            if clear_reply_keyboard(str(ADMIN_CHAT_ID)):
                st_ref["admin_kb_cleared"] = True
        return True

    if text in ADMIN_KB_TEXT:
        if append_command(uid, ADMIN_KB_TEXT[text]):
            mark_pending(chat_id)
        return True

    if text.startswith("/"):
        if append_command(uid, text if cmd == text.split()[0] else " ".join([cmd] + text.split()[1:])):
            mark_pending(chat_id)
        return True

    # A forwarded (or pasted) trading signal: hand the raw text to the executor, which parses it strictly and
    # opens it with the bot's own settings. base64 keeps the multi-line text intact on a one-line command.
    msg_obj = update.get("message") or {}
    is_forward = any(k in msg_obj for k in ("forward_origin", "forward_from_chat", "forward_from", "forward_date", "forward_sender_name"))
    has_digits = bool(re.search(r"\d", text.translate(_FA_DIGITS)))
    # A forwarded message with numbers always goes to the executor: if it is not a usable signal the admin is told
    # exactly why (instead of silently getting the menu).
    if looks_like_signal(text) or (is_forward and has_digits and not text.startswith("/")):
        payload = base64.b64encode(text[:3500].encode("utf-8")).decode("ascii")
        if append_command(uid, f"/fwdsignal b64:{payload}"):
            mark_pending(chat_id)
        return True

    send_menu()
    return True


STATE_REF: dict = {}       # points at the bridge state dict for the admin-keyboard flag


# --------------------------------------------------------------------------- callbacks
def handle_self_service_callback(update: dict, q: dict, chat_id: str) -> bool:
    """Button taps from a subscriber's own chat. Only 'cmd:/<self-service command>' and
    'ask:<subscriber prompt>' do anything; /connect_enc is never accepted from a button (it needs the
    encryption path in the wizard). Anything else is ignored, exactly like a stranger's message."""
    msg = q.get("message") or {}
    if (msg.get("chat") or {}).get("type") != "private":
        answer_callback(str(q.get("id", "")))
        return True
    data = str(q.get("data", ""))
    meta = _meta_of(q.get("from") or {})
    if user_rate_limited(chat_id):
        answer_callback(str(q.get("id", "")), "A little slower please 🙏")
        return True
    if data == "wiz:cancel":
        _wizard.pop(chat_id, None)
        answer_callback(str(q.get("id", "")), "Cancelled")
        append_command(int(update["update_id"]), "/menu", chat_id=chat_id, meta=meta)
        return True
    if data.startswith("wz:"):
        answer_callback(str(q.get("id", "")))
        handle_wizard_button(update, chat_id, data[3:], False, meta)
        return True
    if data.startswith("ask:"):
        answer_callback(str(q.get("id", "")))
        start_wizard(chat_id, data, False)
        return True
    if data.startswith("cmd:"):
        command = data[len("cmd:"):].strip()
        cmd = command.split()[0].lower() if command else ""
        if cmd in SELF_SERVICE_COMMANDS and cmd != "/connect_enc":
            _wizard.pop(chat_id, None)
            answer_callback(str(q.get("id", "")), "⏳ Working…")
            if append_command(int(update["update_id"]), command, chat_id=chat_id, meta=meta):
                mark_pending(chat_id)
            return True
    answer_callback(str(q.get("id", "")))
    return True


def handle_callback(update: dict) -> bool:
    q = update.get("callback_query") or {}
    msg = q.get("message") or {}
    cb_chat_id = str(msg.get("chat", {}).get("id"))
    if cb_chat_id != ADMIN_CHAT_ID:
        return handle_self_service_callback(update, q, cb_chat_id)
    data = str(q.get("data", ""))
    uid = int(update["update_id"])
    qid = str(q.get("id", ""))

    if data == "menu":
        answer_callback(qid)
        _wizard.pop(cb_chat_id, None)
        send_menu()
        return True
    if data == "wiz:cancel":
        answer_callback(qid, "Cancelled")
        _wizard.pop(cb_chat_id, None)
        send_menu()
        return True
    if data in ADMIN_PRESETS:
        answer_callback(qid)
        text, rows = preset_menu(data)
        send_message(text, inline_keyboard=rows)
        return True
    if data.startswith("m:") and data[2:] in ADMIN_SUBMENUS:
        answer_callback(qid)
        _wizard.pop(cb_chat_id, None)
        text, rows = submenu(data[2:])
        send_message(text, inline_keyboard=rows)
        return True
    if data == "users_menu":
        answer_callback(qid)
        text, rows = submenu("users")
        send_message(text, inline_keyboard=rows)
        return True
    if data == "close_one_help":
        answer_callback(qid, "⏳ Working…")
        if append_command(uid, "/positions"):
            mark_pending(cb_chat_id)
        return True
    if data.startswith("wz:"):
        answer_callback(qid)
        handle_wizard_button(update, cb_chat_id, data[3:], True, {})
        return True
    if data.startswith("ask:"):
        answer_callback(qid)
        if not start_wizard(cb_chat_id, data, True):
            send_message("⚠️ This option was not recognized.", inline_keyboard=[[B("📋 Menu", "menu")]])
        return True
    if data.startswith("ack:"):
        answer_callback(qid, "⏳ Working…")
        if append_command(uid, f"/ack {data[len('ack:'):]}"):
            mark_pending(cb_chat_id)
        return True
    if data.startswith("cmd:"):
        answer_callback(qid, "⏳ Working…")
        _wizard.pop(cb_chat_id, None)
        if append_command(uid, data[4:].strip()):
            mark_pending(cb_chat_id)
        return True
    answer_callback(qid)
    return False


_FAST_SIGNAL = {"pending": False}   # set when a channel post was just relayed: push it at once


def poll_telegram(state: dict) -> bool:
    offset = int(state.get("telegram_update_offset", 0))
    r = requests.get(API + "/getUpdates", params={
        "offset": offset,
        "timeout": LONG_POLL_SECONDS,
        "allowed_updates": json.dumps(["channel_post", "message", "callback_query"]),
    }, timeout=LONG_POLL_SECONDS + 10)
    r.raise_for_status()
    body = r.json()
    if not body.get("ok"):
        raise RuntimeError(str(body))

    changed = False
    signal_lines: list[str] = []
    for update in body.get("result", []):
        uid = int(update.get("update_id", 0))
        state["telegram_update_offset"] = max(int(state.get("telegram_update_offset", 0)), uid + 1)
        post = update.get("channel_post") or {}
        if post and str(post.get("chat", {}).get("id")) == CHANNEL_ID:
            text = post.get("text") or post.get("caption")
            if text:
                message_id = post.get("message_id")
                signal_lines.append(json.dumps({
                    "update_id": uid,
                    "message_id": message_id,
                    "signal_id": f"{CHANNEL_ID}:{message_id}" if message_id else str(uid),
                    "ts": time.time(),
                    # Telegram's own message timestamp, NOT when the relay got
                    # around to forwarding it. If this bridge (or the Windows
                    # executor) was offline and catches up on a backlog of
                    # channel posts in one go, "ts" above would show the
                    # catch-up moment for all of them - useless for staleness
                    # checks. "posted_at" is what the executor actually
                    # compares its age against.
                    "posted_at": post.get("date"),
                    "text": text,
                    # The chart the signal bot attached to the post (largest size). The executor re-sends it with
                    # the "signal received" card so admin and subscribers see exactly what is about to be traded.
                    **({"photo": post["photo"][-1].get("file_id")} if post.get("photo") else {}),
                }, ensure_ascii=False))
                changed = True
        if update.get("message"):
            changed |= handle_message(update)
        if update.get("callback_query"):
            changed |= handle_callback(update)

    if signal_lines:
        append_lines(SIGNALS, signal_lines)
        _FAST_SIGNAL["pending"] = True
        log.info("Relayed %d Telegram channel posts to signals.jsonl", len(signal_lines))
    return changed or bool(body.get("result"))


TOOBIT_SIGNUP_URL = "https://www.toobit.com/en-US/register?invite_code=WRLPrM"


def _ticb_allowed_links() -> set:
    """t.me links a subscriber button may carry besides the signup link: the TICB signal bot (renew) and the other executor bot."""
    out = set()
    for var in ("TICB_BOT_USERNAME", "OTHER_EXECUTOR_BOT_USERNAME"):
        u = os.environ.get(var, "").strip().lstrip("@")
        if re.fullmatch(r"[A-Za-z0-9_]{4,64}", u):
            out.add(f"https://t.me/{u}")
    return out


def _sanitize_user_buttons(rows: list) -> list:
    """Defense in depth: a button in a subscriber's chat may only be 'cmd:<self-service command>',
    'ask:<prompt>', or the wizard cancel. Anything else is dropped before Telegram ever sees it."""
    out = []
    for row in rows:
        kept = []
        for b in row:
            d = str(b.get("callback_data", ""))
            ct = b.get("copy_text")
            ctext = str(ct.get("text", "")) if isinstance(ct, dict) else ""
            if ctext and not d and not b.get("url") and (re.fullmatch(r"\d{13,19}", ctext) or re.fullmatch(r"[A-Za-z0-9]{20,120}", ctext)):
                kept.append({"text": str(b.get("text", "📋 Copy"))[:60], "copy_text": {"text": ctext}})   # card number / wallet address only
            elif b.get("url") in _ticb_allowed_links() and not d:
                kept.append({"text": str(b.get("text", "🔗"))[:60], "url": b["url"]})   # TICB bot / other executor bot only
            elif b.get("url") == TOOBIT_SIGNUP_URL and not d:
                kept.append({"text": str(b.get("text", "🆕 Sign up on Toobit"))[:60], "url": TOOBIT_SIGNUP_URL})   # the ONLY link a user button may carry
            elif d == "wiz:cancel":
                kept.append(b)
            elif d.startswith("ask:") and d.split(":")[1] in PROMPTS and PROMPTS[d.split(":")[1]].get("admin") is not True:
                kept.append(b)
            elif d.startswith("cmd:") and d[4:].split()[:1] and d[4:].split()[0].lower() in SELF_SERVICE_COMMANDS \
                    and d[4:].split()[0].lower() != "/connect_enc":
                kept.append(b)
        if kept:
            out.append(kept)
    return out or [[B("📋 My menu", "cmd:/menu")]]


def relay_outbox(state: dict) -> bool:
    if not OUTBOX.exists():
        return False
    lines = OUTBOX.read_text(encoding="utf-8").splitlines()
    sent = int(state.get("outbox_lines_sent", 0))
    if sent > len(lines):
        sent = 0
    changed = False
    thread_roots = state.setdefault("thread_roots", {})
    for idx in range(sent, len(lines)):
        line = lines[idx].strip()
        if not line:
            state["outbox_lines_sent"] = idx + 1
            changed = True
            continue
        key = None
        buttons = None
        reply_chat_id = None
        kb = None
        mid = None
        photo = None
        doc = None
        doc_name = None
        doc_ts = None
        more = False
        try:
            obj = json.loads(line)
            more = bool(obj.get("more"))
            photo = obj.get("photo") or None
            doc = obj.get("doc") or None
            doc_name = obj.get("doc_name") or None
            doc_ts = obj.get("ts")
            mid = str(obj.get("mid") or "") or None
            text = str(obj.get("text", line))
            key = obj.get("key") or None
            reply_chat_id = obj.get("chat_id") or None
            kb = obj.get("kb") or None
            raw_buttons = obj.get("buttons")
            if raw_buttons:
                # Accept either a single row ([{...}, {...}]) or multiple
                # rows ([[...], [...]]) from executor.py.
                buttons = raw_buttons if isinstance(raw_buttons[0], list) else [raw_buttons]
        except Exception:
            text = line
        # The same outbox message can appear twice (a GitHub write that timed out but was stored, then retried).
        # Each message has a unique id; one already delivered is skipped, never sent again.
        relayed = state.setdefault("relayed_mids", [])
        if mid and mid in relayed:
            log.info("skipping duplicate outbox message %s", mid[:8])
            state["outbox_lines_sent"] = idx + 1
            changed = True
            continue
        # Every message carries a way back to the menu, so nobody is ever left without a button.
        if not buttons:
            buttons = [[B("📋 Menu", "menu")]] if not reply_chat_id or str(reply_chat_id) == ADMIN_CHAT_ID \
                else [[B("📋 My menu", "cmd:/menu")]]
        if reply_chat_id and str(reply_chat_id) != ADMIN_CHAT_ID:
            buttons = _sanitize_user_buttons(buttons)
        try:
            if doc:
                _send = send_document_message
                _args = (doc, doc_name or "", text, doc_ts)
            else:
                _send = send_photo_message if photo else send_message
                _args = (photo, text) if photo else (text,)
            msg_id = _send(
                *_args, inline_keyboard=buttons, chat_id=reply_chat_id,
                # A reply-threaded root message only makes sense within the
                # admin chat's own history - never reuse an admin thread_root
                # for a subscriber's separate chat.
                reply_to_message_id=(thread_roots.get(key) if (key and not reply_chat_id) else None),
            )
            # Thread roots are message ids inside the ADMIN chat only; a
            # subscriber's message id means nothing there and would break
            # later admin replies-to for the same trade key.
            if key and msg_id and key not in thread_roots and not reply_chat_id:
                thread_roots[key] = msg_id
            # The message IS delivered at this point: record it before anything else can fail, so a failure in
            # the optional follow-ups below can never make the same message be sent a second time.
            state["outbox_lines_sent"] = idx + 1
            if mid:
                relayed.append(mid)
                del relayed[:-2000]
            changed = True
            try:
                if more:                                            # more pages follow: keep "working on it" (and its timer) alive
                    _p = (state.get("pending") or {}).get(str(reply_chat_id or ADMIN_CHAT_ID))
                    if _p:
                        _p["ts"] = time.time()
                else:
                    clear_pending(reply_chat_id or ADMIN_CHAT_ID)      # the last page is here: remove "working on it"
                # Nobody (admin or subscriber) gets a persistent bottom keyboard: everything is inline buttons under the
                # messages. Anyone who still has an old one gets it removed silently, once.
                _kb_chat = str(reply_chat_id or ADMIN_CHAT_ID)
                _cleared = state.setdefault("kb_cleared", [])
                if _kb_chat not in _cleared and clear_reply_keyboard(_kb_chat):
                    _cleared.append(_kb_chat)
                    del _cleared[:-20000]
            except Exception:
                log.warning("optional follow-up after outbox message %s failed (message itself was delivered)", idx, exc_info=True)
        except Exception as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            if reply_chat_id and status in (400, 403):
                # Permanent failure for one subscriber's chat (bot blocked,
                # chat deleted, user never started the bot). Retrying would
                # block EVERY message queued behind it - including the admin's
                # - forever, so log it, skip just this message and move on.
                log.error("dropping undeliverable message to user chat %s (HTTP %s): %s", reply_chat_id, status, e)
                if mid:
                    relayed.append(mid)
                    del relayed[:-2000]
            else:
                log.error("outbox delivery failed at line %s: %s", idx, e)
                break
        state["outbox_lines_sent"] = idx + 1
        state["thread_roots"] = thread_roots
        changed = True
    return changed


def self_dispatch_next_run() -> None:
    """Queue the next run of this workflow right now via workflow_dispatch.

    Called near the START of main() (not the end) so that even if this run
    itself crashes or is killed early, the next run has already been queued -
    the 5-minute cron stays as a fallback, but in normal operation the chain
    of self-dispatched runs is what keeps the relay effectively continuous.
    concurrency: cancel-in-progress: false in bridge.yml means a run queued
    while this one is still active simply waits and starts right after,
    instead of overlapping or being dropped.
    """
    if not GH_DISPATCH_TOKEN or not GITHUB_REPOSITORY:
        log.warning("Self-dispatch skipped: GH_DISPATCH_TOKEN or GITHUB_REPOSITORY not set "
                    "(falling back to the 5-minute cron only).")
        return
    url = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/actions/workflows/{BRIDGE_WORKFLOW_FILE}/dispatches"
    try:
        r = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {GH_DISPATCH_TOKEN}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={"ref": GITHUB_REF_NAME},
            timeout=15,
        )
        if r.status_code in (201, 204):
            log.info("Self-dispatch: next relay run queued.")
        else:
            log.error("Self-dispatch failed (HTTP %s): %s", r.status_code, r.text[:300])
    except Exception:
        log.exception("Self-dispatch request failed; relying on the 5-minute cron for the next run")


def pull_latest() -> None:
    """Fast-forward the local checkout to match origin/main.

    Without this, outbox.jsonl entries the Windows executor pushes to GitHub
    *while this job is running* stay invisible until the next run's fresh
    checkout - i.e. admin notifications (trade opened, target hit, command
    results, errors) could sit unsent for most of a ~275s window. --ff-only
    means this is a no-op (safely skipped and retried next cycle) whenever
    there are local commits still waiting to be pushed, so it can never
    clobber anything this process itself just wrote.
    """
    try:
        subprocess.run(["git", "fetch", "origin", "main"], check=True,
                       capture_output=True, text=True, timeout=20)
        subprocess.run(["git", "merge", "--ff-only", "origin/main"], check=True,
                       capture_output=True, text=True, timeout=20)
    except Exception as e:
        log.info("pull_latest skipped/failed this cycle (will retry): %s", e)


def check_executor_heartbeat(state: dict) -> bool:
    """Alert the admin directly if the Windows executor has gone silent
    (crashed, PC powered off, lost internet, etc.). Nothing else in this
    system can detect that on its own - a dead executor can't push its own
    "I'm down" message - so this is the one place that can. Alerts once when
    it goes stale and once when it recovers, not on every check. Returns
    True when the debounce flag changed, so the caller knows to push it.
    """
    try:
        if not HEARTBEAT_FILE.exists():
            return False  # executor.py not yet updated to write one, or first run
        data = json.loads(HEARTBEAT_FILE.read_text(encoding="utf-8"))
        age = time.time() - float(data.get("ts", 0))
        was_down = bool(state.get("executor_down_alerted"))
        if age > HEARTBEAT_STALE_SECONDS:
            if not was_down:
                send_message(
                    f"🔴 Warning: the Executor has shown no sign of activity for about {age/60:.0f} minutes "
                    f"(the system may be off, the internet cut, or a program error). Please "
                    f"check its status — until it is active again no new signal is executed and no trade is managed."
                )
                state["executor_down_alerted"] = True
                return True
        elif was_down:
            send_message("🟢 The Executor is active again and sending updates.")
            state["executor_down_alerted"] = False
            return True
    except Exception:
        log.exception("heartbeat check failed")
    return False


def git_sync_and_push() -> None:
    ensure_runtime_files()
    subprocess.run(["git", "config", "user.name", "telegram-github-bridge"], check=True)
    subprocess.run(["git", "config", "user.email", "actions@users.noreply.github.com"], check=True)
    subprocess.run(["git", "add", "signals.jsonl", "commands.jsonl", "outbox.jsonl", "bridge_state.json"], check=True)
    subprocess.run(["git", "add", "-A", "--", "exports"], check=False, capture_output=True)    # stages deletions of delivered exports
    if subprocess.run(["git", "diff", "--cached", "--quiet"]).returncode == 0:
        return
    subprocess.run(["git", "commit", "-m", f"chore: telegram relay @ {int(time.time())} [skip ci]"], check=True)
    for attempt in range(5):
        r = subprocess.run(["git", "push", "origin", "HEAD:main"], capture_output=True, text=True)
        if r.returncode == 0:
            return
        if attempt == 4:
            raise RuntimeError(r.stderr[-1500:])
        subprocess.run(["git", "fetch", "origin", "main"], check=False)
        subprocess.run(["git", "rebase", "origin/main"], check=False)
        time.sleep(1 + attempt)


def main() -> None:
    self_dispatch_next_run()  # queue our successor first, before anything else can fail
    try:
        ensure_runtime_files()
        _run_relay_loop()
    except Exception:
        # The successor run was already dispatched above, so continuous
        # operation is unaffected either way - this only prevents a genuinely
        # unexpected error from showing up as a failed run in the Actions
        # history (which was otherwise possible even though every git/network
        # call inside the loop is already individually guarded below).
        log.exception("Unhandled error in relay loop; successor run already queued")


def _run_relay_loop() -> None:
    try:
        setup_bot_commands()
    except Exception:
        log.exception("setup_bot_commands failed (non-fatal, continuing)")
    state = load_state()
    STATE_REF["state"] = state
    _load_wizard(state)
    start = time.time()
    last_push = 0.0
    last_pull = time.time()  # actions/checkout already gave us a fresh copy
    changed_since_push = False
    log.info("Telegram-GitHub relay started for %.0fs", RUNTIME_SECONDS)
    while time.time() - start < RUNTIME_SECONDS:
        now = time.time()
        if now - last_pull >= PULL_MIN_INTERVAL_SECONDS:
            pull_latest()
            last_pull = time.time()
            changed_since_push |= check_executor_heartbeat(state)

        try:
            changed_since_push |= poll_telegram(state)
        except Exception:
            log.exception("Telegram polling failed")
        if _FAST_SIGNAL["pending"]:
            # A signal is time-critical: commit+push it BEFORE the slower outbox/indicator work and without the
            # minimum push interval, so the executor sees it as early as possible.
            _FAST_SIGNAL["pending"] = False
            try:
                save_state(state)
                git_sync_and_push()
                changed_since_push = False
            except Exception:
                changed_since_push = True
                log.exception("fast signal push failed; the normal push retries next cycle")
            last_push = time.time()
        try:
            changed_since_push |= relay_outbox(state)
        except Exception:
            log.exception("outbox relay failed")
        try:
            changed_since_push |= tick_pending(state)
        except Exception:
            log.exception("pending indicator tick failed")
        _persist_wizard(state)
        save_state(state)

        now = time.time()
        if changed_since_push and (now - last_push) >= PUSH_MIN_INTERVAL_SECONDS:
            try:
                git_sync_and_push()
                changed_since_push = False
            except Exception:
                log.exception("git push failed; will retry next cycle")
            last_push = now
        time.sleep(0.15)

    if changed_since_push:
        try:
            git_sync_and_push()
        except Exception:
            log.exception("final git push failed")
    log.info("Telegram-GitHub relay finished")


if __name__ == "__main__":
    main()
