import asyncio
import os
import sys

from telethon import TelegramClient, types
from telethon.tl.functions.help import GetConfigRequest

API_ID = 27819828
API_HASH = "697659831acf9ea476a0346692c494dd"


BOT_TOKEN = os.environ.get("BOT_TOKEN")
CHAT_ID = os.environ.get("CHAT_ID")
MESSAGE_THREAD_ID = os.environ.get("MESSAGE_THREAD_ID")
COMMIT_URL = os.environ.get("COMMIT_URL")
COMMIT_MESSAGE = os.environ.get("COMMIT_MESSAGE")
RUN_URL = os.environ.get("RUN_URL")
TITLE = os.environ.get("TITLE")
VERSION = os.environ.get("VERSION")
BRANCH = os.environ.get("BRANCH")
MSG_TEMPLATE = """
**{title}**
Branch: {branch}
#ci_{version}
```
{commit_message}
```
[Commit]({commit_url})
[Workflow run]({run_url})
""".strip()


def get_caption():
    msg = MSG_TEMPLATE.format(
        title=TITLE,
        branch=BRANCH,
        version=VERSION,
        commit_message=COMMIT_MESSAGE,
        commit_url=COMMIT_URL,
        run_url=RUN_URL,
    )
    if len(msg) > 1024:
        msg = COMMIT_URL
    if BRANCH == "dev":
        msg += "\n⚠️⚠️**DEV VERSION, PLEASE BACKUP BEFORE INSTALLATION**⚠️⚠️"
        msg += "\n⚠️⚠️**测试版，安装前请备份**⚠️⚠️"
    return msg


def check_environ():
    global CHAT_ID, MESSAGE_THREAD_ID
    if BOT_TOKEN is None:
        print("[-] Invalid BOT_TOKEN")
        exit(1)
    if CHAT_ID is None:
        print("[-] Invalid CHAT_ID")
        exit(1)
    else:
        CHAT_ID = int(CHAT_ID)
    if COMMIT_URL is None:
        print("[-] Invalid COMMIT_URL")
        exit(1)
    if COMMIT_MESSAGE is None:
        print("[-] Invalid COMMIT_MESSAGE")
        exit(1)
    if RUN_URL is None:
        print("[-] Invalid RUN_URL")
        exit(1)
    if TITLE is None:
        print("[-] Invalid TITLE")
        exit(1)
    if VERSION is None:
        print("[-] Invalid VERSION")
        exit(1)
    if BRANCH is None:
        print("[-] Invalid BRANCH")
        exit(1)
    if MESSAGE_THREAD_ID is None:
        print("[!] No MESSAGE_THREAD_ID detected, sending to main chat")
        MESSAGE_THREAD_ID = None
    else:
        try:
            MESSAGE_THREAD_ID = int(MESSAGE_THREAD_ID)
        except ValueError:
            print("[-] Invalid MESSAGE_THREAD_ID format, ignoring")
            MESSAGE_THREAD_ID = None


async def main():
    print("[+] Uploading to telegram")
    check_environ()
    files = sys.argv[1:]
    print("[+] Files:", files)
    if len(files) <= 0:
        print("[-] No files to upload")
        exit(1)
    print("[+] Logging in Telegram with bot")
    script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    session_dir = os.path.join(script_dir, "ksubot")
    async with await TelegramClient(
        session=session_dir, api_id=API_ID, api_hash=API_HASH
    ).start(bot_token=BOT_TOKEN) as bot:
        caption = [""] * len(files)
        caption[-1] = get_caption()
        print("[+] Caption: ")
        print("---")
        print(caption)
        print("---")
        print("[+] Sending")

        reply_to_param = (
            types.InputReplyParameters(reply_to_msg_id=MESSAGE_THREAD_ID)
            if MESSAGE_THREAD_ID
            else None
        )
        await bot.send_file(
            entity=CHAT_ID,
            file=files,
            caption=caption,
            reply_to=reply_to_param,
            parse_mode="markdown",
        )
        print("[+] Done!")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"[-] An error occurred: {e}")
