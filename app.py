import os
import time
import re
import logging
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
    TextMessage,
    PushMessageRequest,
    FlexMessage,
    FlexBubble,
    # FlexImage,
    FlexBox,
    FlexText,
    # FlexIcon,
    # FlexButton,
    # FlexSeparator,
    # FlexContainer,
)

from linebot.v3.webhooks import (
    MessageEvent,
    TextMessageContent
)

app = Flask(__name__)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    message_text = event.message.text
    with ApiClient(configuration) as api_client:
        line_bot_api = MessagingApi(api_client)

        urls = extract_urls(message_text)

        if urls:
            urls_list = '\n\r'.join(urls)
            line_bot_api.reply_message_with_http_info(
                ReplyMessageRequest(
                    reply_token=event.reply_token,
                    messages=[
                        TextMessage(text=f'กำลังตรวจสอบ:\n\r{urls_list}')
                    ]
                )
            )
            source = get_source_id_base_on_source_type(event.source)

            for url in urls:

                response_message = virustotal_scan_url(url)
                # flex_bubble = FlexBubble(
                #     direction='ltr',
                #     body=FlexBox(
                #         layout='vertical',
                #         contents=[
                #             FlexText(text=url),
                #             FlexText(text=response_message)
                #         ]
                #     )
                # )

                line_bot_api.push_message(
                    PushMessageRequest(
                        to=source,
                        messages=[TextMessage(
                            text=response_message)]
                    ))


def extract_urls(text):
    url_regex = re.compile(
        r'((https?://)?(www\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/[^\s]*)?)'
    )
    urls = url_regex.findall(text)
    # Extract the full match from each tuple returned by findall
    urls = [match[0] for match in urls]

    logger.info(f"Extracted URLs and domain names: {urls}")
    return urls


def get_source_id_base_on_source_type(event_source):
    if (event_source.type == 'user'):
        return event_source.user_id
    elif (event_source.type == 'group'):
        return event_source.group_id
    elif (event_source.type == 'room'):
        return event_source.room_id


def virustotal_scan_url(url):
    logger.info(f'Analyzing URL: {url}')
    client = vt.Client(VIRUSTOTAL_API_KEY)
    analysis = client.scan_url(url)

    while True:
        analysis_report = client.get_object('/analyses/{}', analysis.id)
        if analysis_report.status == 'completed':
            break
        time.sleep(10)

    for engine_name in analysis_report.results:
        data = analysis_report.results[engine_name]
        engine_result = data['result']
        logger.info(f'=== Detailed results ===')
        logger.info(f'{engine_name}: {engine_result}')
        logger.info(f'========================')

    for stat in analysis_report.stats:
        data = analysis_report.stats[stat]
        logger.info(f'=== Statistic ===')
        logger.info(f'{stat}: {data}')
        logger.info(f'=================')

    if analysis_report.stats['malicious'] > 0:
        return f'ลิ้งค์นี้ {url} ไม่ปลอดภัย พบว่ามีโปรแกรมประสงค์ร้ายแฝงอยู่ในลิงค์ค่ะ'
    if analysis_report.stats['suspicious'] > 5:
        return f'ลิ้งค์นี้ {url} น่าสงสัยค่ะ ควรระมัดระวังนะคะ '
    else:
        return f'ลิ้งค์นี้ {url} ดูเหมือนจะปลอดภัย แต่เช็คให้ชัวร์ก่อนนะคะ'


if __name__ == '__main__':
    app.run(debug=True)
