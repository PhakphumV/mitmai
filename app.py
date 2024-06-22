import os
from flask import Flask, request, abort
from linebot.v3 import (
    WebhookHandler
)
from linebot.v3.exceptions import (
    InvalidSignatureError
)
from linebot.v3.messaging import (
    Configuration,
    ApiClient,
    MessagingApi,
    ReplyMessageRequest,
    TextMessage
)
from linebot.v3.webhooks import (
    MessageEvent,
    TextMessageContent
)

app = Flask(__name__)

# LINE Bot credentials
CHANNEL_SECRET = os.getenv('LINE_CHANNEL_SECRET')
CHANNEL_ACCESS_TOKEN = os.getenv('LINE_CHANNEL_ACCESS_TOKEN')

if CHANNEL_SECRET is None or CHANNEL_ACCESS_TOKEN is None:
    raise ValueError(
        "Please set the CHANNEL_SECRET and CHANNEL_ACCESS_TOKEN environment variables.")


configuration = Configuration(access_token=CHANNEL_ACCESS_TOKEN)
handler = WebhookHandler(CHANNEL_SECRET)


@app.route("/")
def hello_world():
    return 'Hello, World'


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
        app.logger.info(
            "Invalid signature. Please check your channel access token/channel secret.")
        abort(400)

    return 'OK'


@handler.add(MessageEvent, message=TextMessageContent)
def handle_message(event):
    with ApiClient(configuration) as api_client:
        line_bot_api = MessagingApi(api_client)
        line_bot_api.reply_message_with_http_info(
            ReplyMessageRequest(
                reply_token=event.reply_token,
                messages=[TextMessage(text=event.message.text)]
            )
        )

# @handler.add(MessageEvent, message=TextMessage)
# def handle_message(event):
#     user_message = event.message.text

#     line_bot_api.reply_message(
#         event.reply_token,
#         TextSendMessage(text="Received text: "+user_message)
#     )

#     # if user_message.startswith("http://") or user_message.startswith("https://"):
#     #     url_check_result = check_url_safety(user_message)
#     #     line_bot_api.reply_message(
#     #         event.reply_token,
#     #         TextSendMessage(text=url_check_result)
#     #     )
#     # else:
#     #     line_bot_api.reply_message(
#     #         event.reply_token,
#     #         TextSendMessage(text="Please send a valid URL.")
#     #     )


if __name__ == "__main__":
    app.run(debug=True)
