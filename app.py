import json
from flask import Flask, request, jsonify, render_template, Response, redirect, url_for, session, make_response
import openai
from flask_mail import Mail, Message
from flask_cors import CORS, cross_origin
import smtplib
import jwt
import requests
from jwt import PyJWKClient
from pymongo import MongoClient

GOOGLE_AUTH_CLIENT_ID = ""

conversation = []

app = Flask(__name__)

app.secret_key = ''
openai.api_key = 'sk-'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'CaretalkAI'
app.config['MAIL_PASSWORD'] = ''
app.config['MAIL_DEFAULT_SENDER'] = 'caretalkai@gmail.com'
mail = Mail(app)

feedback_db = {}  # This will store feedback as {message_id: feedback}
chats = []

# MongoDB setup
MONGODB_URI="mongodb://localhost:27017/"
MONGO_DB_NAME="MentalHealthcareDB"
COLLECTION_NAME="userHistory"

mongo = MongoClient(MONGODB_URI)
db = mongo[MONGO_DB_NAME]
user_history_col = db['userHistory']

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/send_feedback', methods=['POST'])
def send_feedback():
    data = request.json
    message_id = data.get('messageId')
    feedback = data.get('feedback')
    #storing this here instead of in a database
    feedback_db[message_id] = feedback
    return jsonify({"status": "success", "message": "Feedback received"})

@app.route('/get_response', methods=['POST'])
def get_response():
    user_input = request.json['user_input']
    conversation.append({"role": "user", "content": user_input})
    try:
        response = openai.ChatCompletion.create(
            model="ft:gpt-3.5-turbo-0613:personal::8pmxCD6k",
            messages=[
                {"role": "system", "content": "You are a compassionate and empathetic expert mental health assistant. Your responses should reflect understanding, provide support, and ask questions that a mental health expert might ask to gently guide the conversation. Provide complete and helpful suggestions. You must remember the context, previous messages the user sent in the current chat and respond accordingly. Do not chat about non mental health related topics. Even if the user's message is abrupt, pick the context from previous conversation and reply based on that"},
                {"role": "user", "content": user_input}
            ],
            max_tokens=150
        )
        if response.choices:
            message = response.choices[0].message['content'].strip()
            conversation.append({"role": "ai", "content": message})
        else:
            message = "No response generated."
    except Exception as e:
        message = "Error: " + str(e)
    return jsonify({'message': message})

@app.route('/download_chat_summary', methods=['GET'])
def download_chat_summary():

    chat_summary = getChatSummary()

    #summary = response.choices[0].text.strip()
    print("chat summary is:", chat_summary)

    response = Response(
        chat_summary['choices'][0]['text'],
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment;filename=chat_summary.txt"}
    )

    response.headers['Access-Control-Allow-Origin'] = '*'
    return response
    
def getFullConversation():
    full_conversation = "\n".join([f"{msg['role'].title()}: {msg['content']}" for msg in conversation])
    print(full_conversation, "is the full conversation")
    return full_conversation

def getChatSummary():
    full_conversation = getFullConversation()

    chat_summary = openai.Completion.create(
        engine="gpt-3.5-turbo-instruct",  # Choose a suitable summarization engine
        prompt=f"Provide a clear and concise Summary the following text:\n{[full_conversation]}. In this summary identify context and replace AI with 'mental healthcare expert' and User with you",
        max_tokens=200,  # Adjust for desired summary length (shorter = less detail)
        n=1,  # Number of summaries to generate (usually 1 is enough)
        stop=None,  # Optional stop sequence to indicate summary completion
        temperature=0.7,  # Controls randomness (0 = deterministic, 1 = creative)
    )

    print("summary", chat_summary['choices'][0]['text'])

    return chat_summary

def send_chat_summary_email(recipient, chat_summary):
    """
    Send an email with the chat summary.
    """
    subject = "Chat Summary - CareTalk AI"
    message = Message(subject, recipients=[recipient], body=chat_summary)
    mail.send(message)

@app.route('/email_chat_summary', methods=['POST'])
def email_chat_summary():
    """
    Endpoint to handle sending the chat summary via email.
    """
    chat_summary = getChatSummary()['choices'][0]['text']
    recipient = request.form['email']  # Assuming the email address is sent in a form
    send_chat_summary_email(recipient, chat_summary)
    print("chat summary and email", chat_summary, recipient)
    return {'status': 'success', 'message': 'Email sent successfully.'}

def get_google_signing_key(token):
    keys_url = 'https://www.googleapis.com/oauth2/v3/certs'

    # Utilize PyJWKClient for handling the JWK Set URL
    jwks_client = PyJWKClient(keys_url)
    # This isn't directly used here but shows how you'd get keys for verification later
    return jwks_client.get_signing_key_from_jwt(token)

@app.route('/auth/google', methods=['POST'])
def google_auth():
    # Extract the JWT from the request
    token = request.form['credential']
    client_id = GOOGLE_AUTH_CLIENT_ID

    if not token:
        return jsonify({'error': 'Missing token'}), 400

    try:
        # Fetch Google's public key
        signing_key  = get_google_signing_key(token)

        # Decode and validate the token
        decoded_token = jwt.decode(token, key=signing_key.key, algorithms=['RS256'], audience=client_id, issuer='https://accounts.google.com')
        
        # At this point, the token is valid, and you can use the decoded information
        # Here you could create a user session or perform other authentication logic
        print("Token is valid. Decoded token: ", decoded_token)

        # Respond to the client that the authentication was successful
        response = make_response(redirect('/'))
        response.set_cookie('is_auth', 'true', max_age=60*60*24)  # Example: Expires in 1 day
        response.set_cookie('loggedin_user_email', decoded_token['email'], max_age=60*60*24)  # Example: Expires in 1 day
        response.set_cookie('loggedin_user_fullname', decoded_token['name'], max_age=60*60*24)  # Example: Expires in 1 day
        response.set_cookie('loggedin_user_picture', decoded_token['picture'], max_age=60*60*24)  # Example: Expires in 1 day

        return response

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'error': f'Invalid token: {e}'}), 401

def is_existing_user(email):
    return user_history_col.count_documents({'email': email}) > 0

def create_empty_user_doc(email):
    # If no document exists, create a new one
    user_history_col.insert_one({'email': email, 'chats': []})
    print(f"New document created for {email}")

@app.route('/get_chats_for_user')
def get_chats_for_user():
    email = request.cookies.get('loggedin_user_email')
    print("email", email)
    if not is_existing_user(email):
        return []
    
    user_documents = user_history_col.find({'email': email})
    documents_list = list(user_documents)
    print(f"Email {email} found in the database. Documents': {documents_list}")
    chats = documents_list[0]['chats']
    return documents_list[0]['chats']

def storeChatToMongoDB(email, conversation):
    result = user_history_col.update_one(
        {"email": email},
        {"$push": {"chats": conversation}}
    )

    if result.modified_count > 0:
        print("Successfully appended the conversation.")
    else:
        print("Failed to append the conversation. Check if the document exists.")

    return result


@app.route('/save', methods=['POST'])
def save_chat():
    # Get the full conversation
    conversation = getFullConversation()

    loggedin_user_email = request.cookies.get('loggedin_user_email')
    
    if loggedin_user_email and conversation:
        # Store the conversation into MongoDB
        result = storeChatToMongoDB(email=loggedin_user_email, conversation=conversation)
        if result:
            return jsonify({'success': True, 'message': 'Chat saved successfully.', 'id': str(result)}), 200
        else:
            return jsonify({'success': False, 'message': 'Failed to save chat.'}), 500
    else:
        return jsonify({'success': False, 'message': 'No conversation found to save.'}), 404

    
if __name__ == '__main__':
    full_conversation = []
    app.run(debug=True)
