import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackQueryHandler, ContextTypes

# ================= Configuration =================
TELEGRAM_TOKEN = "YOUR_BOT_TOKEN_HERE"
API_URL = "http://localhost:5002"

# ================= Bot Commands =================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Welcome message"""
    await update.message.reply_text(
        "🛡️ *PhishGuard Bot*\n\n"
        "🔍 *AI-Powered Phishing URL Detector*\n\n"
        "📌 *How to use:*\n"
        "Simply send me any URL and I'll analyze it.\n\n"
        "⚡ *Features:*\n"
        "• Real-time phishing detection\n"
        "• Risk score (0-100%)\n"
        "• Detailed explanation\n"
        "• Safety recommendations\n"
        "• Report suspicious URLs\n\n"
        "🛡️ *Stay safe online!*",
        parse_mode="Markdown"
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📖 *Help*\n\n"
        "Send me a URL like:\n"
        "• `https://google.com`\n"
        "• `http://paypal.com`\n\n"
        "Commands:\n"
        "/start - Welcome message\n"
        "/help - This help\n"
        "/stats - Bot statistics",
        parse_mode="Markdown"
    )

async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show bot stats"""
    try:
        response = requests.get(f"{API_URL}/api/stats", timeout=10)
        data = response.json()
        await update.message.reply_text(
            "📊 *Bot Statistics*\n\n"
            f"🔍 Total scans: {data.get('total_scans', 0)}\n"
            f"🚨 Phishing detected: {data.get('phishing_detected', 0)}\n"
            f"📈 Detection rate: {data.get('success_rate', 0):.1f}%\n"
            f"⚠️ Total threats: {data.get('total_threats', 0)}",
            parse_mode="Markdown"
        )
    except Exception as e:
        await update.message.reply_text(f"❌ Error fetching stats: {str(e)[:100]}")

# ================= URL Checking =================
async def check_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Analyze user URL"""
    url = update.message.text.strip()
    if not url.startswith("http"):
        url = "https://" + url

    waiting_msg = await update.message.reply_text("🔍 *Analyzing URL...* ⏳", parse_mode="Markdown")

    try:
        response = requests.post(
            f"{API_URL}/smart-check",
            json={"url": url},
            headers={"Content-Type": "application/json"},
            timeout=15
        )
        data = response.json()

        is_phishing = data.get("is_phishing") or data.get("prediction") == "phishing"
        score = data.get("score", data.get("confidence", 0))
        explanation = data.get("explanation", "")
        recommendation = data.get("recommendation", "")
        risk_factors = data.get("risk_factors", [])

        if is_phishing:
            icon, status, risk_text = "🚨⚠️", "⚠️ PHISHING DETECTED!", "🔴 HIGH RISK"
        elif score > 40:
            icon, status, risk_text = "⚠️", "⚠️ SUSPICIOUS URL", "🟠 MEDIUM RISK"
        else:
            icon, status, risk_text = "✅", "✅ SAFE URL", "🟢 LOW RISK"

        reply = f"{icon} *{status}*\n\n" \
                f"📊 *Threat Score:* `{score}%`\n" \
                f"🎯 *Risk Level:* {risk_text}\n\n" \
                f"📝 *Analysis:* {explanation}\n\n" \
                f"💡 *Recommendation:* {recommendation}\n"

        if risk_factors:
            reply += "\n⚠️ *Risk Factors:*\n" + "\n".join(f"• `{f}`" for f in risk_factors[:3])

        reply += f"\n\n🔗 *URL:* `{url}`"

        keyboard = [
            [InlineKeyboardButton("📢 Report", callback_data=f"report_{url}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await waiting_msg.edit_text(reply, parse_mode="Markdown", reply_markup=reply_markup)

    except requests.exceptions.ConnectionError:
        await waiting_msg.edit_text("❌ *Error:* Cannot connect to server. Try again later.", parse_mode="Markdown")
    except Exception as e:
        await waiting_msg.edit_text(f"❌ *Error:* `{str(e)[:100]}`", parse_mode="Markdown")

# ================= Reporting =================
async def handle_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    url = query.data.replace("report_", "")

    try:
        response = requests.post(f"{API_URL}/report", json={"url": url}, timeout=10)
        if response.status_code == 200:
            await query.edit_message_text(
                f"✅ *Thank you for reporting!*\n\n"
                f"The URL has been flagged.\n"
                f"Other users will now be warned about this site.\n\n"
                f"🛡️ *Together we make the internet safer!*",
                parse_mode="Markdown"
            )
        else:
            await query.edit_message_text("❌ Failed to report. Please try again.")
    except Exception as e:
        await query.edit_message_text(f"❌ Error: {str(e)[:100]}")

# ================= Main =================
def main():
    if TELEGRAM_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("❌ Set TELEGRAM_TOKEN in telegram_bot.py (from BotFather)")
        return

    app = Application.builder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("stats", stats))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_url))
    app.add_handler(CallbackQueryHandler(handle_report, pattern="report_"))

    print("🤖 PhishGuard Bot running...")
    print(f"   API URL: {API_URL}")
    app.run_polling()

if __name__ == "__main__":
    main()