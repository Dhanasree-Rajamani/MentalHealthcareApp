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
from dotenv import load_dotenv
import os

load_dotenv()

GOOGLE_AUTH_CLIENT_ID = os.getenv('GOOGLE_AUTH_CLIENT_ID')

app = Flask(__name__)

app.secret_key = os.getenv('APP_SECRET_KEY')
openai.api_key = os.getenv('OPENAI_API_KEY')

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'CaretalkAI'
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
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
    session['conversation'] = []  # Reset the conversation every time the main page is loaded
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
    if 'conversation' not in session:
        session['conversation'] = []

    user_input = request.json['user_input']
    
    # Here we add the user input to the session's conversation history.
    session['conversation'].append({"role": "user", "content": user_input})
    
    # Prepare the initial setup guidance along with the conversation history for the model.
    initial_setup = """You are a highly skilled and empathetic mental health assistant, trained to offer support with compassion and understanding. In your responses, reflect deep empathy and offer guidance, echoing the care and insight of a seasoned mental health expert.

Engage deeply by asking open-ended questions, encouraging reflection and discussion.
Provide thoughtful, specific, and actionable advice, tailoring your guidance to the unique context and details shared by the user.
Remember and seamlessly integrate details from the user's previous messages to build a coherent and supportive dialogue. Your memory is key to personalizing the conversation.
Stay focused on topics related to mental health and well-being. Avoid diverting into unrelated subjects, maintaining professional boundaries and relevance.
In cases where the user's input is brief or lacks detail, use your understanding from the ongoing conversation to offer responses that are insightful and nurturing.
Your goal is to be a source of support, offering elaborate guidance and fostering a safe space for users to explore their feelings and challenges.

In addition to the guidelines provided:

Maintain a Singular Focus on Mental Health: Your primary role is to offer support and guidance on issues directly related to mental health and emotional well-being. If the conversation starts to shift towards topics outside of mental health, such as general knowledge, science, math, or any other unrelated subjects, gently redirect the user back to topics of mental health.

Guidance on Redirecting Conversations: When faced with questions or discussions not related to mental health, respond with empathy and understanding, reminding the user of your specific role as a mental health assistant. Offer to continue supporting them with any concerns or questions they have about their mental health and emotional well-being.

Example of Redirecting: If a user asks a question unrelated to mental health, you might respond with: 'I'm here to support you with any mental health concerns you might have. While I can't provide answers to questions outside of this area, I'm interested in how you're feeling today or if there's anything on your mind related to your emotional well-being that you'd like to talk about.'

Ensuring a Safe and Supportive Environment: Your responses should always aim to create a supportive space for users to explore and discuss their feelings, experiences, and challenges related to mental health. Encourage open-ended discussion, reflection, and the expression of emotions, ensuring users feel heard, understood, and cared for.

Remember, your goal is to foster a trusting and empathetic dialogue that focuses solely on mental health and emotional well-being, providing guidance and support tailored to each user's unique experiences and needs"""
    
    conversation_with_setup = [{"role": "system", "content": initial_setup}] + session['conversation']
    
    #conversation_with_setup =  session['conversation']
    
    # Adjust based on your needs to manage memory and ensure effective context utilization.
    max_context_length = 20  
    if len(conversation_with_setup) > max_context_length:
        conversation_with_setup = conversation_with_setup[-max_context_length:]

    try:
        response = openai.ChatCompletion.create(
            #ft:gpt-3.5-turbo-0613:personal::8pmxCD6k
            model="ft:gpt-3.5-turbo-0613:personal::9CB4CCRl",
            messages=conversation_with_setup,
            max_tokens=250,
            temperature = 0.2
        )
        
        if response.choices:
            message = response.choices[0].message['content'].strip()
            # Add AI's response to the session's conversation history.
            session['conversation'].append({"role": "assistant", "content": message})
        else:
            message = "No response generated."
    except Exception as e:
        message = "Error: " + str(e)
    
    session.modified = True  # Important to save changes to the session.
    return jsonify({'message': message})

# @app.route('/get_response', methods=['POST'])
# def get_response():
#     user_input = request.json['user_input']
#     conversation.append({"role": "user", "content": user_input})
#     try:
#         response = openai.ChatCompletion.create(
#             model="ft:gpt-3.5-turbo-0613:personal::8pmxCD6k",
#             messages=[
#                 {"role": "system", "content": "You are a compassionate and empathetic expert mental health assistant. Your responses should reflect understanding, provide support, and ask questions that a mental health expert might ask to gently guide the conversation. Provide complete and helpful suggestions. You must remember the context, previous messages the user sent in the current chat and respond accordingly. Do not chat about non mental health related topics. Even if the user's message is abrupt, pick the context from previous conversation and reply based on that"},
#                 {"role": "user", "content": user_input}
#             ],
#             max_tokens=150
#         )
#         if response.choices:
#             message = response.choices[0].message['content'].strip()
#             conversation.append({"role": "ai", "content": message})
#         else:
#             message = "No response generated."
#     except Exception as e:
#         message = "Error: " + str(e)
#     return jsonify({'message': message})


@app.route('/handle_downvote', methods=['POST'])
def handle_downvote():
    # Check if there is a conversation history
    if 'conversation' not in session or len(session['conversation']) < 2:
        return jsonify({'message': 'No previous interaction found to downvote.'})
    
    # Assume the last message in the conversation is the one to downvote
    # And the previous one is the user's input leading to that response
    feedback_prompt = "The previous response was not satisfactory. Please provide a different perspective or approach."
    
    # Alter the conversation history here to incorporate the feedback
    # For simplicity, let's just add the feedback prompt to the conversation
    # You might want to adjust or remove the last AI response instead
    session['conversation'].append({"role": "system", "content": feedback_prompt})
    
    # Ensure any changes are saved
    session.modified = True
    
    # Since direct calling of `get_response` isn't straightforward in Flask,
    # and to avoid duplicate code, you return an instruction to the client to resend the last user input.
    # This could be handled more elegantly with JavaScript on the client side by automatically resending
    # the last request or by adjusting the UI/UX flow.
    return jsonify({'message': 'Feedback noted. Please resend your last question or statement.'})



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
    
# def getFullConversation():
#     full_conversation = "\n".join([f"{msg['role'].title()}: {msg['content']}" for msg in conversation])
#     print(full_conversation, "is the full conversation")
#     return full_conversation

def getFullConversation():
    # Access the conversation from the session
    if 'conversation':
        full_conversation = "\n".join([f"{msg['role'].title()}: {msg['content']}" for msg in session['conversation']])
        print(full_conversation, "is the full conversation")
        return full_conversation
    else:
        print("The conversation is empty.")
        return "The conversation is empty."


def getChatSummary():
    full_conversation = getFullConversation()

    chat_summary = openai.Completion.create(
        engine="gpt-3.5-turbo-instruct",  # Choose a suitable summarization engine
        prompt=f"Provide a clear and concise Summary the following text:\n{[full_conversation]}. In this summary identify context and replace AI with 'mental healthcare expert' and User with you",
        max_tokens=350,  # Adjust for desired summary length (shorter = less detail)
        n=1,  # Number of summaries to generate (usually 1 is enough)
        stop=None,  # Optional stop sequence to indicate summary completion
        temperature=0.2,  # Controls randomness (0 = deterministic, 1 = creative)
    )

    print("summary", chat_summary['choices'][0]['text'])

    return chat_summary

def send_chat_summary_email(subject, recipient, chat_summary):
    """
    Send an email with the chat summary.
    """
    subject = subject
    message = Message(subject, recipients=[recipient], body=chat_summary)
    mail.send(message)

@app.route('/email_chat_summary', methods=['POST'])
def email_chat_summary():
    """
    Endpoint to handle sending the chat summary via email.
    """
    chat_summary = getChatSummary()['choices'][0]['text']
    recipient = request.form['email']  # Assuming the email address is sent in a form
    send_chat_summary_email("Chat Summary - CareTalk AI", recipient, chat_summary)
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
        response.set_cookie('user_google_auth_token', token, max_age=60*60*24)  # Example: Expires in 1 day

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
    if not is_existing_user(email):
        create_empty_user_doc(email)
    
    result = user_history_col.update_one(
        {"email": email},
        {"$push": {"chats": conversation}}
    )

    if result.modified_count > 0:
        print("Successfully appended the conversation.")
    else:
        print("Failed to append the conversation. Check if the document exists.")

    return result

@app.route('/email_chat_transcript', methods=['POST'])
def email_chat_transcript():
    data = request.get_json()
    email = data['email']
    
    if 'conversation' in session and email:
        # Assuming your conversation is stored in session['conversation']
        conversation = session['conversation']
        chat_transcript = "\n".join([f"{msg['role'].title()}: {msg['content']}" for msg in conversation])
        
        send_chat_summary_email("Chat Transcript - CareTalk AI", email, chat_transcript)
        return jsonify({'status': 'success', 'message': 'Email sent successfully.'})
    else:
        return jsonify({'status': 'error', 'message': 'No conversation found or email not provided.'}), 400



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

@app.route('/signout', methods=['POST'])
def signout():
    token = request.cookies.get('user_google_auth_token')
    if token:
        # Google's endpoint for revoking tokens
        requests.post('https://oauth2.googleapis.com/revoke',
                      params={'token': token},
                      headers = {'content-type': 'application/x-www-form-urlencoded'})
    

    # Clear cookies
    response = make_response(redirect('/'))
    response.set_cookie('is_auth', '', expires=0)
    response.set_cookie('loggedin_user_email', '', expires=0)
    response.set_cookie('loggedin_user_fullname', '', expires=0)
    response.set_cookie('loggedin_user_picture', '', expires=0)
    response.set_cookie('user_google_auth_token', '', expires=0)
    return response

    
if __name__ == '__main__':
    conversation = []
    full_conversation = []
    app.run(debug=True)
