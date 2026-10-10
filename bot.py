#!/usr/bin/env python3
import os, asyncio, json, logging, time
from datetime import datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes)
from scanner import RDPScanner

load_dotenv()
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
if not TOKEN:
    raise ValueError("TELEGRAM_BOT_TOKEN مفقود في .env")

ALLOWED_CHATS = {int(x) for x in os.getenv("ALLOWED_CHATS", "").split(",") if x.strip()}

def is_authorized(chat_id: int) -> bool:
    return chat_id in ALLOWED_CHATS

async def _deny(update: Update):
    msg = "🚫 غير مصرح."
    if update.callback_query:
        await update.callback_query.answer(msg, show_alert=True)
    elif update.message:
        await update.message.reply_text(msg)

RESULTS_DIR = Path("scan_results"); RESULTS_DIR.mkdir(exist_ok=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)
if not ALLOWED_CHATS:
    logger.warning("⚠️ ALLOWED_CHATS فارغ — البوت مفتوح للكل. اضبط .env.")

active_scans = {}
scan_settings = {}
completed_scans = {}

def get_settings(chat_id: int) -> dict:
    if chat_id not in scan_settings:
        scan_settings[chat_id] = {"concurrency": 1000, "timeout": 1.0, "grab_banner": True}
    return scan_settings[chat_id]

def format_eta(seconds: float) -> str:
    if seconds <= 0: return "…"
    td = timedelta(seconds=int(seconds))
    if td.days: return f"{td.days}d {td.seconds//3600}h"
    h, m = td.seconds // 3600, (td.seconds % 3600) // 60
    if h: return f"{h}h {m}m"
    if m: return f"{m}m {td.seconds%60}s"
    return f"{int(seconds)}s"

def main_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔍 بدء فحص", callback_data="menu_scan"), InlineKeyboardButton("⚙️ الإعدادات", callback_data="menu_settings")],
        [InlineKeyboardButton("▶️ استئناف مسح", callback_data="menu_resume"), InlineKeyboardButton("📋 السجل", callback_data="menu_history")],
        [InlineKeyboardButton("🧹 مسح الحالة", callback_data="menu_clear"), InlineKeyboardButton("❤️ المساعدة", callback_data="menu_help")],
    ])

def settings_menu(chat_id: int):
    s = get_settings(chat_id)
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(f"🔹 التوازي: {s['concurrency']}", callback_data="set_nop"), InlineKeyboardButton("➖", callback_data="set_concurrency_down"), InlineKeyboardButton("➕", callback_data="set_concurrency_up")],
        [InlineKeyboardButton(f"⏱️ المهلة: {s['timeout']}s", callback_data="set_nop"), InlineKeyboardButton("➖", callback_data="set_timeout_down"), InlineKeyboardButton("➕", callback_data="set_timeout_up")],
        [InlineKeyboardButton(f"🔍 Banner: {'✅' if s['grab_banner'] else '❌'}", callback_data="set_toggle_banner")],
        [InlineKeyboardButton("🔙 رجوع", callback_data="menu_back")],
    ])

def scan_controls():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("⏹ إيقاف", callback_data="stop_scan"), InlineKeyboardButton("⏸ إيقاف مؤقت", callback_data="pause_scan")],
        [InlineKeyboardButton("📊 عرض", callback_data="show_results"), InlineKeyboardButton("📁 TXT", callback_data="save_txt")],
        [InlineKeyboardButton("📊 CSV", callback_data="save_csv"), InlineKeyboardButton("📋 JSON", callback_data="save_json")],
        [InlineKeyboardButton("🔙 القائمة", callback_data="menu_back_to_main")],
    ])

def _get_results(chat_id: int):
    if chat_id in active_scans and active_scans[chat_id].get("found"):
        return active_scans[chat_id]["found"]
    if chat_id in completed_scans:
        return completed_scans[chat_id].get("found", [])
    return []

async def _send_main_menu(context: ContextTypes.DEFAULT_TYPE, chat_id: int):
    state = RDPScanner.load_state()
    msg = "🏠 <b>القائمة الرئيسية</b>\nبوت فحص RDP.\n\n🔍 أرسل ملف <code>.txt</code>."
    if state and not state.get("finished"):
        msg += f"\n⚠️ <b>مسح غير مكتمل:</b> {len(state.get('networks',[]))} نطاق | 🟢 {len(state.get('found_results',[]))} نتيجة"
    await context.bot.send_message(chat_id, msg, parse_mode="HTML", reply_markup=main_menu())

async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update.effective_chat.id):
        return await _deny(update)
    await _send_main_menu(context, update.effective_chat.id)

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    if not is_authorized(chat_id):
        return await _deny(update)
    if chat_id in active_scans:
        await update.message.reply_text("⏳ فحص نشط. أوقفه أولاً.", reply_markup=main_menu())
        return
    doc = update.message.document
    if not doc or not (doc.file_name or "").lower().endswith('.txt'):
        await update.message.reply_text("📛 أرسل ملف .txt", reply_markup=main_menu())
        return

    loading_msg = await update.message.reply_text("📥 جاري التحميل...")
    try:
        file = await context.bot.get_file(doc.file_id)
        content = (await file.download_as_bytearray()).decode('utf-8', errors='ignore')
    except Exception:
        await loading_msg.edit_text("❌ فشل.")
        return

    temp = RDPScanner()
    networks = temp.parse_cidr_file(content)
    if not networks:
        await loading_msg.edit_text("❌ لا نطاقات.", reply_markup=main_menu())
        return

    RDPScanner.clear_state()
    settings = get_settings(chat_id)
    scanner = RDPScanner(concurrency=settings["concurrency"], timeout=settings["timeout"], grab_banner=settings["grab_banner"])
    approx = scanner.count_hosts(networks)

    await loading_msg.edit_text(
        f"🔍 <b>بدء الفحص...</b>\n📋 {len(networks)} نطاق | 🌐 {approx:,} IP\n⚙️ {scanner.concurrency} اتصال | ⏱️ {scanner.timeout}s\n🔍 Banner: {'✅' if scanner.grab_banner else '❌'}\n\n🟢 <i>منطلق...</i>",
        parse_mode="HTML", reply_markup=scan_controls()
    )
    status_msg = loading_msg

    await _run_scan_task(context, chat_id, scanner, networks, approx, status_msg)

async def _run_scan_task(context, chat_id, scanner, networks, approx, status_msg, state=None):
    async def progress_cb(current, total, ip, status, start_time):
        try:
            if current % 2000 != 0 and current > 10 and current != total: return
            pct = (current/total)*100 if total else 0
            elapsed = time.time() - start_time
            rate = current/elapsed if elapsed else 0
            eta = ((total-current)/rate) if rate else 0
            found_count = len(active_scans.get(chat_id, {}).get("found", []))
            await context.bot.edit_message_text(
                chat_id=chat_id, message_id=status_msg.message_id,
                text=f"🔍 <b>الفحص جارٍ...</b>\n📋 {len(networks)} نطاق | 🌐 {total:,} IP\n✅ {current:,} ({pct:.1f}%)\n🟢 مفتوح: {found_count}\n⚡ {rate:.0f} IP/s | ⏳ {format_eta(eta)}\n🔹 <code>{ip}</code>\n\n<i>مستمر...</i>",
                parse_mode="HTML", reply_markup=scan_controls(),
            )
        except Exception: pass

    async def found_cb(entry):
        data = active_scans.get(chat_id)
        if data: data["found"].append(entry)

    scanner.on_progress(progress_cb)
    scanner.on_found(found_cb)

    active_scans[chat_id] = {
        "scanner": scanner, "message_id": status_msg.message_id, "found": [],
        "total": approx, "networks": networks, "start_time": time.time(),
    }

    async def run_scan():
        try:
            found_results, _ = await scanner.scan(networks, state=state)
        except Exception as e:
            logger.error(f"Scan error: {e}"); found_results = []

        data = active_scans.pop(chat_id, None)
        if not data: return
        fc = len(found_results)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        try:
            with open(RESULTS_DIR / f"scan_{ts}.json", "w") as f:
                json.dump({"scanned": data["total"], "total": data["total"], "found_count": fc, "found_results": found_results, "finished_at": time.time()}, f)
        except Exception as e: logger.error(f"save error: {e}")
        completed_scans[chat_id] = {"found": found_results}
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id, message_id=status_msg.message_id,
                text=f"✅ <b>اكتمل!</b>\n🌐 فُحص: {data['total']:,}\n🟢 <b>مفتوح: {fc}</b>\n\n📁 أزرار التصدير.",
                parse_mode="HTML", reply_markup=scan_controls(),
            )
        except Exception: pass

    asyncio.create_task(run_scan())

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    chat_id = query.message.chat_id
    data = query.data
    if not is_authorized(chat_id):
        await query.answer("🚫 غير مصرح.", show_alert=True)
        return
    await query.answer()

    if data == "menu_scan":
        await query.edit_message_text("📂 أرسل ملف <code>.txt</code>.", parse_mode="HTML", reply_markup=main_menu())
    elif data == "menu_settings":
        await query.edit_message_text("⚙️ <b>الإعدادات</b>", parse_mode="HTML", reply_markup=settings_menu(chat_id))
    elif data == "menu_resume":
        state = RDPScanner.load_state()
        if state and not state.get("finished"):
            nw, fnd = state.get("networks", []), state.get("found_results", [])
            await query.edit_message_text(
                f"⏳ <b>استئناف</b>\n📋 {len(nw)} نطاق | 🟢 {len(fnd)} مفتوح\n\nاضغط ▶️",
                parse_mode="HTML",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("▶️ استئناف", callback_data="do_resume")], [InlineKeyboardButton("🔙 رجوع", callback_data="menu_back")]])
            )
        else:
            await query.edit_message_text("😕 لا مسح غير مكتمل.", reply_markup=main_menu())
    elif data == "do_resume":
        if chat_id in active_scans:
            await query.edit_message_text("⏳ فحص نشط حالياً.", reply_markup=main_menu()); return
        state = RDPScanner.load_state()
        if not state or state.get("finished"):
            await query.edit_message_text("😕 لا شيء للاستئناف.", reply_markup=main_menu()); return
        networks = state.get("networks", [])
        if not networks:
            await query.edit_message_text("❌ الحالة تالفة.", reply_markup=main_menu()); return
        settings = get_settings(chat_id)
        scanner = RDPScanner(concurrency=settings["concurrency"], timeout=settings["timeout"], grab_banner=settings["grab_banner"])
        approx = scanner.count_hosts(networks)
        msg = await query.edit_message_text(
            f"▶️ <b>استئناف...</b>\n📋 {len(networks)} نطاق | 🌐 {approx:,} IP",
            parse_mode="HTML", reply_markup=scan_controls()
        )
        await _run_scan_task(context, chat_id, scanner, networks, approx, msg, state=state)
    elif data == "menu_history":
        files = sorted(RESULTS_DIR.glob("scan_*.json"), key=lambda f: f.stat().st_mtime, reverse=True)[:5]
        if not files:
            await query.edit_message_text("📭 لا سجل.", reply_markup=main_menu()); return
        msg = "<b>📋 آخر المسوحات:</b>\n\n"
        for f in files:
            try:
                d = json.loads(f.read_text())
                dt = datetime.fromtimestamp(d.get("finished_at", 0)).strftime("%Y-%m-%d %H:%M")
                msg += f"📅 {dt} | 🟢 {d.get('found_count',0)} | 🌐 {d.get('scanned',0):,}\n"
            except Exception: continue
        await query.edit_message_text(msg, parse_mode="HTML", reply_markup=main_menu())
    elif data == "menu_clear":
        RDPScanner.clear_state()
        await query.edit_message_text("🧹 تم المسح.", reply_markup=main_menu())
    elif data == "menu_help":
        await query.edit_message_text("<b>🔍 بوت RDP</b>\n\n• أرسل .txt\n• Asyncio فقط\n• Banner بعد الفحص", parse_mode="HTML", reply_markup=main_menu())
    elif data == "menu_back":
        try: await query.message.delete()
        except Exception: pass
        await _send_main_menu(context, chat_id)
    elif data == "menu_back_to_main":
        try: await query.message.delete()
        except Exception: pass
        await _send_main_menu(context, chat_id)
    elif data == "set_concurrency_up":
        s = get_settings(chat_id); s["concurrency"] = min(2000, s["concurrency"] + 100)
        await query.edit_message_text("⚙️ <b>الإعدادات</b>", parse_mode="HTML", reply_markup=settings_menu(chat_id))
    elif data == "set_concurrency_down":
        s = get_settings(chat_id); s["concurrency"] = max(100, s["concurrency"] - 100)
        await query.edit_message_text("⚙️ <b>الإعدادات</b>", parse_mode="HTML", reply_markup=settings_menu(chat_id))
    elif data == "set_timeout_up":
        s = get_settings(chat_id); s["timeout"] = min(5.0, round(s["timeout"] + 0.5, 1))
        await query.edit_message_text("⚙️ <b>الإعدادات</b>", parse_mode="HTML", reply_markup=settings_menu(chat_id))
    elif data == "set_timeout_down":
        s = get_settings(chat_id); s["timeout"] = max(0.5, round(s["timeout"] - 0.5, 1))
        await query.edit_message_text("⚙️ <b>الإعدادات</b>", parse_mode="HTML", reply_markup=settings_menu(chat_id))
    elif data == "set_toggle_banner":
        s = get_settings(chat_id); s["grab_banner"] = not s["grab_banner"]
        await query.edit_message_text("⚙️ <b>الإعدادات</b>", parse_mode="HTML", reply_markup=settings_menu(chat_id))
    elif data == "set_nop":
        pass
    elif data == "stop_scan":
        sd = active_scans.get(chat_id)
        if sd:
            sd["scanner"].stop()
            found = sd.get("found", []); current = sd.get("total", 0)
            completed_scans[chat_id] = {"found": found}
            active_scans.pop(chat_id, None)
            await query.edit_message_text(f"⏹ <b>أُوقف.</b>\n🔹 فُحص: {current:,} | 🟢 {len(found)}", parse_mode="HTML", reply_markup=main_menu())
            if found:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                await context.bot.send_document(chat_id, document="\n".join([e["ip"] for e in found]).encode(), filename=f"rdp_{ts}.txt", caption=f"🟢 {len(found)} IP")
        else:
            await query.edit_message_text("لا فحص.", reply_markup=main_menu())
    elif data == "pause_scan":
        sd = active_scans.get(chat_id)
        if sd and not sd["scanner"]._paused:
            sd["scanner"].pause()
            await query.edit_message_text("⏸ <b>مؤقت.</b>\nاضغط ⏸ مرة أخرى للاستئناف.", parse_mode="HTML", reply_markup=scan_controls())
        elif sd and sd["scanner"]._paused:
            sd["scanner"].resume()
            await query.edit_message_text("▶️ <b>استؤنف.</b>", parse_mode="HTML", reply_markup=scan_controls())
        else:
            await query.edit_message_text("لا فحص.", reply_markup=main_menu())
    elif data == "show_results":
        found = _get_results(chat_id)
        if not found:
            await query.answer("لا نتائج", show_alert=True); return
        txt = "\n".join([f"{e.get('ip','?')} | {e.get('protocol','?')} | {e.get('os_hint','?')}" for e in found[:30]])
        more = f"\n... +{len(found)-30}" if len(found) > 30 else ""
        await query.message.reply_text(f"🟢 <b>نتائج:</b>\n<pre>{txt}{more}</pre>", parse_mode="HTML")
    elif data in ["save_txt", "save_csv", "save_json"]:
        found = _get_results(chat_id)
        if not found:
            await query.answer("لا نتائج", show_alert=True); return
        fmt = data.split("_")[1]; ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if fmt == "txt":
            content = "\n".join([e["ip"] for e in found]); fn = f"rdp_{ts}.txt"
        elif fmt == "csv":
            content = "IP,Port,Protocol,OS Hint\n" + "\n".join([f'{e["ip"]},3389,{e.get("protocol","?")},{e.get("os_hint","?")}' for e in found]); fn = f"rdp_{ts}.csv"
        elif fmt == "json":
            content = json.dumps(found, indent=2, default=str); fn = f"rdp_{ts}.json"
        else:
            return
        await context.bot.send_document(chat_id, document=content.encode(), filename=fn, caption=f"🟢 {len(found)} IP | {fmt.upper()}")

def main():
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    app.add_handler(CallbackQueryHandler(button_handler))
    logger.info("🚀 Bot running (pure async)...")
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)

if __name__ == "__main__":
    main()
