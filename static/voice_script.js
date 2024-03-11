document.addEventListener('DOMContentLoaded', function() {
    const voiceSelect = document.getElementById('voiceGender');
    let speechSynthesisVoice = null;

    function updateVoice() {
        const voices = window.speechSynthesis.getVoices();
        const gender = voiceSelect.value;
        speechSynthesisVoice = voices.find(voice => voice.name.includes(gender === 'male' ? 'Male' : 'Female'));
    }

    // Wait for speechSynthesis to load voices.
    if (speechSynthesis.onvoiceschanged !== undefined) {
        speechSynthesis.onvoiceschanged = updateVoice;
    }

    const recognition = new (window.SpeechRecognition || window.webkitSpeechRecognition)();
    recognition.lang = 'en-US';
    recognition.interimResults = false;

    document.getElementById('start-voice').addEventListener('click', function() {
        recognition.start();
    });

    recognition.onresult = function(event) {
        const speechToText = event.results[0][0].transcript;
        displayMessage(speechToText, 'user');
        sendMessage(speechToText);
    };

    recognition.onerror = function(event) {
        console.error('Recognition error', event.error);
    };

    document.getElementById('send-btn').addEventListener('click', function() {
        const userInput = document.getElementById('user-input').value;
        if (userInput.trim() !== '') {
            displayMessage(userInput, 'user');
            document.getElementById('user-input').value = '';
            sendMessage(userInput);
        }
    });

    function sendMessage(message) {
        // Simulate AI response for demonstration. Replace with fetch request as needed.
        const aiResponse = "This is a simulated response."; // Simulate AI response
        displayMessage(aiResponse, 'ai');
        speak(aiResponse);
    }

    function displayMessage(message, sender) {
        const div = document.createElement('div');
        div.textContent = message;
        div.className = 'message ' + (sender === 'user' ? 'user-message' : 'ai-message');
        document.getElementById('chat-box').appendChild(div);
    }

    function speak(message) {
        const speech = new SpeechSynthesisUtterance(message);
        speech.voice = speechSynthesisVoice;
        window.speechSynthesis.speak(speech);
    }

    voiceSelect.addEventListener('change', updateVoice);
});
