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
from langchain.embeddings.openai import OpenAIEmbeddings
from pinecone import Pinecone

load_dotenv()

pc = Pinecone(api_key= os.getenv('PINECONE_KEY'), environment='gcp-starter')

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

embeddings = OpenAIEmbeddings(
    model = 'text-embedding-ada-002',
    openai_api_key= openai.api_key
)

index_name = 'test'

index = pc.Index(index_name)

text_field = 'text'  # the metadata field that contains our text

from langchain.vectorstores import Pinecone

# initialize the vector store object
vectorstore = Pinecone(
    index, embeddings.embed_query, text_field
)

@app.route('/')
def home():
    session['conversation'] = []  # Reset the conversation every time the main page is loaded
    if 'loggedin_user_email' in request.cookies:
        email = request.cookies['loggedin_user_email']
        session['chat_summary_context'] = get_user_chats_summary()
    return render_template('index.html')

@app.route('/send_feedback', methods=['POST'])
def send_feedback():
    data = request.json
    message_id = data.get('messageId')
    feedback = data.get('feedback')
    #storing this here instead of in a database
    feedback_db[message_id] = feedback
    return jsonify({"status": "success", "message": "Feedback received"})

def augment_prompt(query: str):
    # get top 3 results from knowledge base
    results = vectorstore.similarity_search(query, k=3)
    # get the text from the results
    source_knowledge = "\n".join([x.page_content for x in results])

    # feed into an augmented prompt
    augmented_prompt = f"""

    Understand the user's question and leverage your knowledge to provide a helpful response. If the question requires expertise beyond your current capabilities, use source_knowledge to access additional information. If source_knowledge is not relevant, simply provide a polite response acknowledging any limitations.
    
    Contexts:
    {source_knowledge}

    Examples:


    Query: {query}"""
    return augmented_prompt

@app.route('/get_response', methods=['POST'])
def get_response():
    if 'conversation' not in session:
        session['conversation'] = []

    user_input = request.json['user_input']
    
    
    # Here we add the user input to the session's conversation history.
    session['conversation'].append({"role": "user", "content": user_input})

    #user_email = request.cookies.get('loggedin_user_email')
    #print("user email", user_email)
    
    # Get summarized context of the user's previous chats
    #chat_summary_context = get_user_chats_summary()
    #Here is previous information about the user : {chat_summary_context} Take this context whenever there is need in the conversation.
    email = request.cookies.get('loggedin_user_email')
    chat_summary_context = None
    if email:
        chat_summary_context = session.get('chat_summary_context', "")
        print("chat summary context: ", chat_summary_context)    
        print("end summary")
    if chat_summary_context:
        # Prepare the initial setup guidance along with the conversation history for the model.
        initial_setup = """You are a mental health assistant, trained to proactively recall and integrate details from previous conversations to offer personalized and compassionate support. When responding, follow these guidelines: 1)Proactively Use Context: Continually integrate relevant details from previous interactions (summarized in the {chat_summary_context}), even if the user does not explicitly refer to past discussions. This helps in maintaining a coherent dialogue that reflects a deep understanding of the user's ongoing mental health journey. 2) Show Empathy and Provide Tailored Advice: Deliver empathetic responses that are also enriched with specific advice tailored to the user's unique emotional and mental health needs. Link current concerns with past discussions proactively, highlighting progress, recurring issues, or introducing new strategies as appropriate.
    3) Maintain Focus on Mental Health: Your primary role is to assist with mental health concerns. If the conversation shifts, gently redirect back to the topics of emotional and mental health. Explain your specialized role and express your readiness to support them in this specific area.
    4) Ensure Immediate Safety Response: If the conversation involves expressions of immediate harm to oneself or others, such as suicidal thoughts, intentions to harm someone, or destructive behavior, prioritize the user's safety above all else. Promptly provide information on appropriate emergency services, such as crisis hotlines or emergency numbers. Encourage the user to seek immediate help from these services or from local authorities to ensure their safety and the safety of others.
    5) Encourage Reflective Dialogue: Use open-ended questions to foster deeper reflection and encourage the user to explore their feelings and challenges, aiding in building a therapeutic dialogue.
    6) Ensure Safety and Support: Create a supportive environment where emotions can be freely expressed, and the user feels heard and cared for, all while maintaining professional boundaries and relevance to mental health.
    7) Adapt Interaction Based on Evolving Needs: Continually assess whether to build on the existing context or address new information specifically. Always aim to provide insightful and nurturing responses based on the evolving needs of the user.
    8) Immediate Crisis Response Protocol: When a user expresses thoughts or intentions of self-harm, suicide, violence towards others, or any other form of severe, immediate risk, the model must prioritize user safety by immediately recommending emergency intervention. The response should include directing the user to contact emergency services (like calling 911 in the U.S. or its equivalent elsewhere) or a specific crisis hotline relevant to their expressed issue. Additionally, the model should clearly state that it is not equipped to handle acute emergencies and reinforce the importance of seeking immediate professional assistance.
    Example of Proactive Contextual Memory Integration: User: 'I've been feeling a bit overwhelmed lately.' Response: 'I'm sorry to hear you're feeling overwhelmed. Last time we talked about similar feelings when discussing work stress. Have you noticed any specific triggers recently that might be contributing to this, or are there any new stressors we haven't discussed yet?'
    This refined approach encourages you to be proactive in recalling and applying past conversation details, thereby enhancing the continuity and depth of support, much like a real-life mental health professional."""
    else:
        initial_setup = """You are a mental health assistant, trained to offer personalized and compassionate support. When responding, follow these guidelines:
    1) Show Empathy and Provide Tailored Advice: Deliver empathetic responses that are also enriched with specific advice tailored to the user's unique emotional and mental health needs.
    2) Maintain Focus on Mental Health: Your primary role is to assist with mental health concerns. If the conversation shifts, gently redirect back to the topics of emotional and mental health.
    3) Ensure Immediate Safety Response: If the conversation involves expressions of immediate harm to oneself or others, such as suicidal thoughts, intentions to harm someone, or destructive behavior, prioritize the user's safety above all else.
    4) Encourage Reflective Dialogue: Use open-ended questions to foster deeper reflection and encourage the user to explore their feelings and challenges.
    5) Ensure Safety and Support: Create a supportive environment where emotions can be freely expressed, and the user feels heard and cared for.
    6) Adapt Interaction Based on Evolving Needs: Continually assess whether to build on the existing context or address new information specifically.
    7) Immediate Crisis Response Protocol: When a user expresses thoughts or intentions of self-harm, suicide, violence towards others, or any other form of severe, immediate risk, the model must prioritize user safety by immediately recommending emergency intervention."""

    conversation_with_setup = [{"role": "system", "content": initial_setup},
                               {"role": "user", "content": augment_prompt(user_input)}] + session['conversation']
    
    #conversation_with_setup =  session['conversation']
    
    # Adjust based on your needs to manage memory and ensure effective context utilization.
    max_context_length = 20  
    if len(conversation_with_setup) > max_context_length:
        conversation_with_setup = conversation_with_setup[-max_context_length:]

    try:
        response = openai.ChatCompletion.create(
            #ft:gpt-3.5-turbo-0613:personal::8pmxCD6k
            #ft:gpt-3.5-turbo-0613:personal::9CB4CCRl
            #ft:gpt-3.5-turbo-0613:personal::9FnG44zU
            model="ft:gpt-3.5-turbo-0613:personal::9FqV28I6",
            messages=conversation_with_setup,
            max_tokens=400,
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


@app.route('/downvote', methods=['POST'])
def downvote():
    if 'conversation' not in session or len(session['conversation']) < 2:
        print("no response")
        return jsonify({'message': 'No previous response to downvote.'}), 400

    # Remove the last bot response
    last_user_message = session['conversation'][-2]
    session['conversation'].pop()

    # Optionally, adjust your setup or parameters here to generate a different response
    # For simplicity, this example just repeats the process of getting a response to the last user input.
    try:
        response = openai.ChatCompletion.create(
            model="ft:gpt-3.5-turbo-0613:personal::9CB4CCRl",
            messages=[{"role": "system", "content": last_user_message["content"]}],  # This might need to be adjusted
            max_tokens=250,
            temperature=0.6  # Adjusting temperature for variety
        )
        
        if response.choices:
            new_message = response.choices[0].message['content'].strip()
            # Replace the last response with the new one
            session['conversation'].append({"role": "assistant", "content": new_message})
        else:
            new_message = "No response generated."
    except Exception as e:
        new_message = "Error: " + str(e)

    session.modified = True
    print("new conv: ", session['conversation'], new_message)
    return jsonify({'message': new_message})



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
        prompt=f"""Please provide a detailed summary of the provided conversations between a user and an AI assistant, designated as {full_conversation}. This summary should encompass:

Identification of Main Topics: Describe each main topic discussed throughout the conversations.
Key Questions and Responses: List out the significant questions raised by the user and the corresponding answers provided by the AI.
Emerging Themes or Issues: Note any recurring themes or challenges that are evident across the dialogues.
Contextual Background: Offer any relevant context that might influence the understanding of the conversations, such as the user's intent or the AI's guidance.
Outcome and Resolution: Highlight any conclusions reached or solutions proposed during the exchanges.
Ensure that the summary is clear, structured, and devoid of redundant information, providing a concise yet thorough overview of the dialogue exchanges.
Refer to the AI as 'mental healthcare expert.'
Use 'you' to refer to the User's perspective.""",
        temperature=0.1,
        max_tokens=550,
        n=1,
        stop=None
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

def get_user_chats_summary():
    """
    Fetch all chats for the given user email, summarize them, and return the summary.
    """
    chats = get_chats_for_user()
    # summary = get_user_chats_summary(chats)
    # print("chat summary", summary)
    
    if not chats:
        return "No chats found for the user."
    
    # Join all chats into a single string
    all_chats = "\n".join(chats)
    print("all chats", all_chats)
    
    # Now, let's summarize the chats
    summary = openai.Completion.create(
        engine="gpt-3.5-turbo-instruct",  # Use an appropriate engine for summarization
        prompt=f"""Please provide a detailed summary of the provided conversations between a user and an AI assistant, designated as {all_chats}. This summary should encompass:

Identification of Main Topics: Describe each main topic discussed throughout the conversations.
Key Questions and Responses: List out the significant questions raised by the user and the corresponding answers provided by the AI.
Emerging Themes or Issues: Note any recurring themes or challenges that are evident across the dialogues.
Contextual Background: Offer any relevant context that might influence the understanding of the conversations, such as the user's intent or the AI's guidance.
Outcome and Resolution: Highlight any conclusions reached or solutions proposed during the exchanges.
Ensure that the summary is clear, structured, and devoid of redundant information, providing a concise yet thorough overview of the dialogue exchanges.""",
        temperature=0.1,
        max_tokens=550,
        n=1,
        stop=None
    #     top_p=1.0,
    #     frequency_penalty=0.0,
    #     presence_penalty=0.0
    )
    print("summary",  summary['choices'][0]['text'])
    if summary.choices:
        return summary.choices[0].text.strip()
    else:
        return "Failed to generate a summary."


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
        #session['chat_summary_context'] = get_user_chats_summary()
    
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
    # chats = documents_list[0]['chats']
    # summary = get_user_chats_summary(chats)
    # print("chat summary", summary)
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
    if 'chat_summary_context' in session:
        del session['chat_summary_context']

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
