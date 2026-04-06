# telegram_bot.py - PhishGuard Bot (Fixed Version)

import re
import requests
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackQueryHandler, ContextTypes

# ============= CONFIGURATION (EDIT THESE) =============
TELEGRAM_TOKEN = "8781348498:AAHiHKxC_nmO39Kslm4QsM4jmF_qVnSfikc"
API_URL = "http://localhost:5002"        # Your local API URL
# ======================================================

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# URL validation pattern
url_pattern = re.compile(
    r'^(https?:\/\/)'                 # http:// or https://
    r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}' # domain
    r'(\/.*)?$'                       # optional path
)

# ============= HANDLERS =============

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message"""
    await update.message.reply_text(
        "🛡️ *Welcome to PhishGuard Bot*\n\n"
        "I help you detect phishing URLs.\n\n"
        "*How to use:* Send me any URL.\n\n"
        "Example: `https://google.com`\n\n"
        "*Features:*\n"
        "• AI-powered phishing detection\n"
        "• Risk score (0-100%)\n"
        "• Detailed explanation\n\n"
        "Stay safe online! 🔒",
        parse_mode="Markdown"
    )

async def check_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Analyze URL sent by user"""
    url = update.message.text.strip()
    
    # Add https if no protocol
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Validate URL format
    if not url_pattern.match(url):
        await update.message.reply_text(
            "❌ Please send a valid URL.\nExample: `https://google.com`",
            parse_mode="Markdown"
        )
        return
    
    # Send waiting message
    waiting_msg = await update.message.reply_text("🔍 Analyzing URL... Please wait ⏳")
    
    try:
        # Call your API
        response = requests.post(
            f"{API_URL}/smart-check",
            json={"url": url},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code != 200:
            await waiting_msg.edit_text(f"❌ API Error: Status {response.status_code}")
            return
        
        data = response.json()
        
        # Extract results
        is_phishing = data.get('is_phishing', False) or data.get('prediction') == 'phishing'
        score = data.get('score', data.get('confidence', 0))
        explanation = data.get('explanation', 'No explanation available')
        recommendation = data.get('recommendation', 'No recommendation')
        risk_factors = data.get('risk_factors', [])
        
        # Format response
        if is_phishing:
            icon = "🚨⚠️"
            status = "⚠️ PHISHING DETECTED!"
            risk_level = "🔴 HIGH RISK"
        elif score > 40:
            icon = "⚠️"
            status = "⚠️ SUSPICIOUS URL"
            risk_level = "🟠 MEDIUM RISK"
        else:
            icon = "✅"
            status = "✅ SAFE URL"
            risk_level = "🟢 LOW RISK"
        
        reply = f"""
{icon} *{status}*

📊 *Threat Score:* `{score}%`
🎯 *Risk Level:* {risk_level}

📝 *Analysis:* {explanation}

💡 *Recommendation:* {recommendation}
"""
        
        if risk_factors:
            reply += "\n⚠️ *Risk Factors:*\n"
            for factor in risk_factors[:3]:
                reply += f"• `{factor}`\n"
        
        reply += f"\n🔗 *URL:* `{url}`"
        
        # Inline buttons
        keyboard = [
            [
                InlineKeyboardButton("📢 Report", callback_data=f"report_{url}"),
                InlineKeyboardButton("🔄 Check Again", callback_data="check_again")
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await waiting_msg.edit_text(reply, parse_mode="Markdown", reply_markup=reply_markup)
        
    except requests.exceptions.ConnectionError:
        await waiting_msg.edit_text(
            "❌ Cannot connect to server.\n"
            "Make sure the API is running: `python smart_api.py`",
            parse_mode="Markdown"
        )
    except requests.exceptions.Timeout:
        await waiting_msg.edit_text("❌ Request timeout. Please try again.")
    except Exception as e:
        logger.error(f"Error: {e}")
        await waiting_msg.edit_text(f"❌ Error: {str(e)[:100]}")

async def handle_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle report button"""
    query = update.callback_query
    await query.answer()
    
    url = query.data.replace("report_", "")
    
    try:
        response = requests.post(
            f"{API_URL}/report",
            json={"url": url},
            timeout=10
        )
        
        if response.status_code == 200:
            await query.edit_message_text(
                f"✅ *Thank you for reporting!*\n\n"
                f"The URL has been flagged.\n"
                f"Other users will be warned.\n\n"
                f"🛡️ Together we make the internet safer!",
                parse_mode="Markdown"
            )
        else:
            await query.edit_message_text("❌ Failed to report. Please try again.")
    except Exception as e:
        await query.edit_message_text(f"❌ Error: {str(e)[:100]}")

async def handle_check_again(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle check again button"""
    query = update.callback_query
    await query.answer()
    await query.edit_message_text(
        "🔍 Send me a new URL to analyze.\n\n"
        "Example: `https://google.com`",
        parse_mode="Markdown"
    )

# ============= MAIN =============

def main():
    """Run the bot"""
    # Check if token is set
    if TELEGRAM_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("❌ ERROR: Please set your TELEGRAM_TOKEN")
        print("   Get it from @BotFather on Telegram")
        return
    
    print("=" * 50)
    print("🤖 PhishGuard Bot Starting...")
    print(f"   API URL: {API_URL}")
    print("=" * 50)
    
    # Create application
    app = Application.builder().token(TELEGRAM_TOKEN).build()
    
    # Add handlers
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_url))
    app.add_handler(CallbackQueryHandler(handle_report, pattern="report_"))
    app.add_handler(CallbackQueryHandler(handle_check_again, pattern="check_again"))
    
    # Start bot
    print("✅ Bot is running! Press Ctrl+C to stop.")
    app.run_polling()

if __name__ == "__main__":
    main()