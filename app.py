from flask import Flask, request, jsonify, render_template
import openai
from flask import Flask, request, jsonify, Response
from flask_mail import Mail, Message
from flask_cors import CORS
from flask_cors import cross_origin
import smtplib

conversation = []

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

openai.api_key = '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'

app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'CaretalkAI'
app.config['MAIL_PASSWORD'] = 'avpu xgvu sqgu jstl'
app.config['MAIL_DEFAULT_SENDER'] = 'caretalkai@gmail.com'
mail = Mail(app)

feedback_db = {}  # This will store feedback as {message_id: feedback}

@app.route('/')
def home():
    return render_template('index.html')

# @app.route('/text_chat')
# def text_chat():
#     return render_template('text_chat.html')

# @app.route('/voice_chat')
# def voice_chat():
#     return render_template('voice_chat.html')

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
    
def getChatSummary():
    full_conversation = "\n".join([f"{msg['role'].title()}: {msg['content']}" for msg in conversation])

    print(full_conversation, "is the full conversation")

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
        
if __name__ == '__main__':
    full_conversation = []
    app.run(debug=True, port=5001)
