import os
from flask import Flask, request, abort
from linebot import LineBotApi, WebhookHandler
from linebot.exceptions import InvalidSignatureError
from linebot.models import MessageEvent, TextMessage, TextSendMessage
import requests

app = Flask(__name__)

# LINE Bot credentials
CHANNEL_SECRET = os.getenv('LINE_CHANNEL_SECRET')
CHANNEL_ACCESS_TOKEN = os.getenv('LINE_CHANNEL_ACCESS_TOKEN')

if CHANNEL_SECRET is None or CHANNEL_ACCESS_TOKEN is None:
    raise ValueError("Please set the CHANNEL_SECRET and CHANNEL_ACCESS_TOKEN environment variables.")

line_bot_api = LineBotApi(CHANNEL_ACCESS_TOKEN)
handler = WebhookHandler(CHANNEL_SECRET)

@app.route("/callback", methods=['POST'])
def callback():
    # Get X-Line-Signature header value
    signature = request.headers['X-Line-Signature']

    # Get request body as text
    body = request.get_data(as_text=True)
    app.logger.info("Request body: " + body)

    # Handle webhook body
    try:
        handler.handle(body, signature)
    except InvalidSignatureError:
        abort(400)

    return 'OK'

@handler.add(MessageEvent, message=TextMessage)
def handle_message(event):
    user_message = event.message.text

    line_bot_api.reply_message(
        event.reply_token,
        TextSendMessage(text="Received text: "+user_message)
    )

    # if user_message.startswith("http://") or user_message.startswith("https://"):
    #     url_check_result = check_url_safety(user_message)
    #     line_bot_api.reply_message(
    #         event.reply_token,
    #         TextSendMessage(text=url_check_result)
    #     )
    # else:
    #     line_bot_api.reply_message(
    #         event.reply_token,
    #         TextSendMessage(text="Please send a valid URL.")
    #     )

if __name__ == "__main__":
    app.run(debug=True)