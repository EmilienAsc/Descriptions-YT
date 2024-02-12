from flask import Flask, redirect, session, request, render_template, jsonify, flash
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from dotenv import load_dotenv, find_dotenv
import stripe
import os
import requests
import json
from datetime import datetime, timedelta
import threading
import schedule
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.urandom(24)
sitekey="SITE_KEY"
global_video_info_list = {}

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# ----------------------------------------------- CREDITS YT ------------------------------------------------------

credits = 9500

def reset_credits():
    global credits
    credits = 9500  # Reset credit values

def schedule_reset_credits():
    now = datetime.now()
    midnight_pst = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    time_to_midnight = midnight_pst - now
    threading.Timer(time_to_midnight.total_seconds(), reset_credits).start()


# ---------------------------------------------- STRIPE PART ------------------------------------------------------

load_dotenv(find_dotenv()) # ls -a

stripe.set_app_info(
    'stripe-samples/accept-a-payment/payment-element',
    version='0.0.2',
    url='https://github.com/stripe-samples')

stripe.api_version = '2020-08-27'
STRIPE_PUBLISHABLE_KEY="PUBLISHABLE_KEY"
STRIPE_SECRET_KEY="SECRET_KEY"
STRIPE_WEBHOOK_SECRET="WEBHOOK_SECRET"
SECRET_KEY_CAPTCHA="SECRET_KEY_CAPTCHA"
stripe.api_key = STRIPE_SECRET_KEY
videos_to_modify = []

# -----------------------------------------------------------------------------------------------------------------

CLIENT_SECRETS_FILE = "/mysite/client_secret.json"  # Path to your client_secret.json file
API_SERVICE_NAME = "youtube"
API_VERSION = "v3"
SCOPES = ["https://www.googleapis.com/auth/youtube.readonly", "https://www.googleapis.com/auth/youtube.force-ssl"]

# -----------------------------------------------------------------------------------------------------------------

from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField
from wtforms.validators import DataRequired

class MyForm(FlaskForm):
    filterInput = StringField('Filter descriptions that contain:', validators=[DataRequired()])
    remplaceInput = StringField('Remplace with:', validators=[DataRequired()])

# -----------------------------------------------------------------------------------------------------------------


def create_youtube_client(credentials_dict):
    credentials = Credentials(
        token=credentials_dict['token'],
        refresh_token=credentials_dict['refresh_token'],
        token_uri=credentials_dict['token_uri'],
        client_id=credentials_dict['client_id'],
        client_secret=credentials_dict['client_secret']
    )
    return build(API_SERVICE_NAME, API_VERSION, credentials=credentials)


def is_human(captcha_response):
        SECRET_KEY_CAPTCHA = os.getenv('SECRET_KEY_CAPTCHA')
        payload = {'response': captcha_response, 'secret': SECRET_KEY_CAPTCHA}
        response = requests.post("https://www.google.com/recaptcha/api/siteverify", payload)
        response_text = json.loads(response.text)
        return response_text['success']


# -----------------------------------------------------------------------------------------------------------------

@app.route('/')
@limiter.limit("6 per minute", error_message="Suspicious activity detected")
def home():
    return render_template("home.html")


@app.route('/check')
@limiter.limit("6 per minute", error_message="Suspicious activity detected")
def check():
    return render_template("check.html")


@app.route('/pricing')
@limiter.limit("6 per minute", error_message="Suspicious activity detected")
def pricing():
    return render_template("pricing.html")


@app.route('/legal')
@limiter.limit("6 per minute", error_message="Suspicious activity detected")
def legal():
    return render_template("legal.html")


@app.route('/payment')
@limiter.limit("20 per hour", error_message="Suspicious activity detected")
def payment():
    return render_template('index.html')


@app.route('/config', methods=['GET'])
def get_config():
    return jsonify({'publishableKey': STRIPE_PUBLISHABLE_KEY})


@app.route('/create-payment-intent', methods=['GET'])
def create_payment():
    try:
        videos_to_modify = session.get('videos_to_modify', [])
        num_videos_to_modify = len(videos_to_modify)

        required_credits = num_videos_to_modify * 50 # Number of credits taken by update

        global credits
        if credits < required_credits:
            return "We're sorry, we don't have enough credits to perform this action at the moment. Please try again tomorrow."

        # Deduct required credits
        credits -= required_credits

        product_price = 4
        product_quantity = num_videos_to_modify

        intent = stripe.PaymentIntent.create(
            amount=product_price * product_quantity,
            currency='EUR',
            automatic_payment_methods={
                'enabled': True,
            }
        )

        # Send PaymentIntent details to the front end.
        return jsonify({'clientSecret': intent.client_secret})
    except stripe.error.StripeError as e:
        return jsonify({'error': {'message': str(e)}}), 400
    except Exception as e:
        return jsonify({'error': {'message': str(e)}}), 400


@app.route('/return')
def retur():
    payment_intent_id = request.args.get('payment_intent')

    try:
        payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)

        if payment_intent.status == 'succeeded':

            # The payment is successful, carry out your checks and actions here
            videos_to_modify = session.get('videos_to_modify', [])
            filter_input = session.get('filterInput', '')
            replace_input = session.get('remplaceInput', '')
            credentials = session.get('credentials', None)
            youtube = create_youtube_client(credentials)

            for video_id in videos_to_modify:
                video_response = youtube.videos().list(part='snippet', id=video_id).execute()
                video = video_response['items'][0]

                video_id = video['id']
                video_title = video['snippet']['title']
                video_description = video['snippet']['description']
                video_category_id = video['snippet']['categoryId']

                new_description = video_description.replace(filter_input, replace_input)

                youtube.videos().update(
                    part="snippet",
                    body={
                        "id": video_id,
                        "snippet": {
                            "title": video_title,
                            "description": new_description,
                            "categoryId": video_category_id
                        }
                    }
                ).execute()
            session.pop('credentials', None)
            return render_template('return.html', amount=payment_intent.amount / 100)
        else:
            # Payment failed
            return render_template('payment_failure.html')
    except stripe.error.StripeError as e:
        # Manage Stripe errors here
        return render_template('payment_failure.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES)
    flow.redirect_uri = request.url_root + 'callback'
    authorization_url, state = flow.authorization_url(
        access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)


@app.route('/select_videos', methods=['GET', 'POST'])
@limiter.limit("30 per hour", error_message="Suspicious activity detected")
def select_videos():
    global credits

    form = MyForm()

    if form.validate_on_submit():
        try :
            filterInput = form.filterInput.data
            remplaceInput = form.remplaceInput.data
            selected_video_ids = request.form.getlist('videos')

            if filterInput and remplaceInput:
                session['filterInput'] = filterInput
                session['remplaceInput'] = remplaceInput

                videos_to_modify = []

                for video_id in session.get('videos_ids', []):
                    if video_id in selected_video_ids:
                        videos_to_modify.append(video_id)

                if videos_to_modify:
                    session['videos_to_modify'] = videos_to_modify
                    return redirect('/payment')

                session.pop('video_ids', None)
                flash("No video has been selected", "error")
                redirect('/select_videos')
        except Exception as e:
            return f"Une erreur s'est produite : {str(e)}", 500 

    credentials = session.get('credentials', None)

    if not credentials:
        return redirect('/login')

    youtube = create_youtube_client(credentials)

    # Get the user's string ID
    channels_response = youtube.channels().list(part='snippet', mine=True).execute()
    user_channel_id = channels_response['items'][0]['id']

    # Get videos from the user's channel
    response = youtube.search().list(part='id', type='video', maxResults=5000, channelId=user_channel_id).execute()
    video_items = response.get('items', [])
    video_ids = [video['id']['videoId'] for video in video_items]

    required_credits = len(video_ids)  # Deduction of 1 credit per video searched (api quota)
    if credits < required_credits:
        return "We're sorry, we don't have enough credits to perform this action at the moment. Please try again tomorrow."

    # Update remaining credits
    credits -= required_credits

    video_info_list = {}

    # For each video, get full details
    videos_ids = []
    for video_id in video_ids:
        video_response = youtube.videos().list(part='snippet', id=video_id).execute()
        video = video_response['items'][0]

        video_id = video['id']
        title = video['snippet']['title']
        description = video['snippet']['description']
        published_date = video['snippet']['publishedAt']
        videos_ids.append(video_id)

        video_info = {
            'video_id': video_id,
            'title': title,
            'description': description,
            'published_date': published_date
        }

        video_info_list[video_id] = video_info

    # Store user-specific video information in the user's session
    session['videos_ids'] = videos_ids

    return render_template("chose_videos.html", video_info_list=video_info_list, form=form)


@app.route('/callback')
def callback():
    state = session['state']
    flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES, state=state)
    flow.redirect_uri = request.url_root + 'callback'
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials

    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret
    }

    return redirect('/select_videos')


@app.route('/privacy')
@limiter.limit("6 per minute", error_message="Suspicious activity detected")
def privacy():
    return render_template("privacy_policy.html")

if __name__ == "__main__":
    schedule_reset_credits()
    app.run()
