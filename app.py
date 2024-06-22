import os
import requests
import vt
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

# VIRUSTOTAL API credentials
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

if CHANNEL_SECRET is None or CHANNEL_ACCESS_TOKEN is None:
    raise ValueError(
        'Please set the CHANNEL_SECRET and CHANNEL_ACCESS_TOKEN environment variables.')


configuration = Configuration(access_token=CHANNEL_ACCESS_TOKEN)
handler = WebhookHandler(CHANNEL_SECRET)


@app.route('/')
def hello_world():
    return 'Hello, World'


@app.route('/callback', methods=['POST'])
def callback():
    # Get X-Line-Signature header value
    signature = request.headers['X-Line-Signature']

    # Get request body as text
    body = request.get_data(as_text=True)
    app.logger.info('Request body: ' + body)

    # Handle webhook body
    try:
        handler.handle(body, signature)
    except InvalidSignatureError:
        app.logger.info(
            'Invalid signature. Please check your channel access token/channel secret.')
        abort(400)

    return 'OK'


@handler.add(MessageEvent, message=TextMessageContent)
def handle_message(event):
    with ApiClient(configuration) as api_client:
        line_bot_api = MessagingApi(api_client)

        # line_bot_api.reply_message_with_http_info(
        #     ReplyMessageRequest(
        #         reply_token=event.reply_token,
        #         messages=[TextMessage(text=event.message.text)]
        #     )
        # )
        user_message = event.message.text
        if user_message.startswith("http://") or user_message.startswith("https://"):
            response_message = virustotal_scan_url(user_message)
            line_bot_api.reply_message_with_http_info(
                ReplyMessageRequest(
                    reply_token=event.reply_token,
                    messages=[TextMessage(text=response_message)]
                )
            )


def virustotal_scan_url(url):
    client = vt.Client(VIRUSTOTAL_API_KEY)
    # VT_API_URL = 'https://www.virustotal.com/api/v3/urls'
    # headers = {
    #     'x-apikey': VIRUSTOTAL_API_KEY,
    # }

    # params = {
    #     'url': url,
    # }
    analysis = client.scan_url(url)
    return f"{analysis}"

    # response = requests.get(VT_API_URL, headers=headers, params=params)
    # if response.status_code == 200:
    #     result = response.json()
    #     if result['data']['attributes']['stats']['malicious'] > 0:
    #         return f"The URL {url} is unsafe. It has been flagged as malicious by VirusTotal."
    #     else:
    #         return f"The URL {url} appears to be safe."
    # else:
    #     return f"Failed to check URL safety. Status code: {response.status_code}"


if __name__ == "__main__":
    app.run(debug=True)
