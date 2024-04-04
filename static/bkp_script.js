document.addEventListener('DOMContentLoaded', function() {
    const chatModal = document.getElementById('chat-modal');
    const closeButton = document.getElementById('close-chat');
    const sendButton = document.getElementById('send-btn');
    const userInput = document.getElementById('user-input');
    const chatBox = document.getElementById('chat-box');
    const recordButton = document.getElementById('record-voice');
    const voiceModal = document.getElementById('voice-chat-modal');
    const closeVoiceChatButton = document.getElementById('close-voice-chat');
    const voiceGenderSelect = document.getElementById('voice-gender-select'); // Dropdown for selecting voice gender

    let isRecording = false;
    let recognition;


    document.getElementById('download-chat').addEventListener('click', downloadChatSummary);
    document.getElementById('download-voice-chat').addEventListener('click', downloadVoiceChatSummary);

    document.getElementById('emailForm').addEventListener('submit', function(e) {
        e.preventDefault(); // Prevent the default form submission
        sendChatSummaryEmail();
    });

    document.getElementById('emailFormVoice').addEventListener('submit', function(e) {
        e.preventDefault(); // Prevent the default form submission
        sendChatSummaryEmail();
    });
    
    
    function sendChatSummaryEmail() {
        const email = document.getElementById('email-input').value;
    
        // Use Fetch API to send a POST request to your Flask endpoint
        fetch('/email_chat_summary', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `email=${encodeURIComponent(email)}`,
        })
        .then(response => response.json())
        .then(data => console.log(data.message))
        .catch(error => console.error('Error sending email:', error));
    }
    
    
    // Open text chat modal
    document.getElementById('open-chat').addEventListener('click', function(event) {
        event.preventDefault();
        chatModal.style.display = 'block';
        displayMessage("Hi! I am your AI assistant! I can help with your mental health. Let us have a conversation!", 'ai');
    });

    // Close text chat modal
    closeButton.addEventListener('click', function() {
        chatModal.style.display = 'none';

        // Confirm with the user
        var userWantsToSave = confirm("Do you want to save your chat before closing?");
    });

    sendButton.addEventListener('click', function() {
        sendUserInput();
    });
    
    // Add an event listener to the userInput field for the 'keydown' event
    userInput.addEventListener('keydown', function(event) {
        // Check if the key pressed is the Enter key
        if (event.key === 'Enter') {
            event.preventDefault(); // Prevent the default action to avoid submitting a form if it's part of one
            sendUserInput();
        }
    });
    
    function sendUserInput() {
        const message = userInput.value.trim();
        if (message) {
            displayMessage(message, 'user');
            sendMessageToServer(message);
            userInput.value = ''; // Clear input after sending
        }
    }
    

    function displayMessage(message, sender) {
        const messageDiv = document.createElement('div');
        messageDiv.textContent = message;
        messageDiv.className = sender === 'user' ? 'user-message' : 'ai-message';
        chatBox.appendChild(messageDiv);
        chatBox.scrollTop = chatBox.scrollHeight; // Auto-scroll to the latest message
    }

    function sendMessageToServer(message) {
        // Simulate server request/response. Replace this with your actual AJAX call to the server.
        fetch('/get_response', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ user_input: message }),
        })
        .then(response => response.json())
        .then(data => {
            displayMessage(data.message, 'ai'); // Display AI response
        })
        .catch(error => {
            console.error('Error:', error);
            displayMessage('Sorry, something went wrong.', 'ai'); // Fallback message
        });
    }

    // Function to toggle recording on and off
    function toggleRecording() {
        if (isRecording) {
            recognition.stop();
            isRecording = false;
            recordButton.textContent = 'Record Voice'; // Change button text to indicate recording can be started
        } else {
            startSpeechRecognition();
            isRecording = true;
            recordButton.textContent = 'Stop Recording'; // Change button text to indicate recording can be stopped
        }
    }

        // Initialize speech recognition
        function initSpeechRecognition() {
            recognition = new (window.SpeechRecognition || window.webkitSpeechRecognition)();
            recognition.lang = 'en-US';
            recognition.continuous = false;
            recognition.interimResults = false;
    
            recognition.onresult = function(event) {
                const transcript = event.results[0][0].transcript;
                console.log('Transcript:', transcript);
                getAIResponse(transcript); // Send transcript to get AI's response
                isRecording = false; // Reset recording state
                recordButton.textContent = 'Record Voice'; // Reset button text
            };
    
            recognition.onerror = function(event) {
                console.error('Speech recognition error', event.error);
                isRecording = false; // Reset recording state
                recordButton.textContent = 'Record Voice'; // Reset button text
            };
        }

    // Start speech recognition
    function startSpeechRecognition() {
        recognition.start();
    }

    // Open voice chat modal and prepare for recording
    document.getElementById('open-voice-chat').addEventListener('click', function(event) {
        event.preventDefault();
        voiceModal.style.display = 'block';
        initSpeechRecognition(); // Prepare speech recognition but don't start yet

        // Greet the user with the AI's voice message in the selected gender voice as soon as the voice message window opens
        speakAIResponse("Hi! I am your AI assistant! I can help with your mental health. Let us have a conversation!");
    });

    // Close voice chat modal
    closeVoiceChatButton.addEventListener('click', function() {
        voiceModal.style.display = 'none';
        if (isRecording) {
            recognition.stop(); // Ensure recording is stopped if modal is closed
        }
        speechSynthesis.cancel(); // Stop any ongoing speech synthesis
    });

    // Toggle recording on button click
    recordButton.addEventListener('click', function() {
        toggleRecording();
    });

    function getAIResponse(message) {
        // Display user's message in the chat UI
        displayMessage(message, 'user');
        
        fetch('/get_response', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ user_input: message }),
        })
        .then(response => response.json())
        .then(data => {
            // Display AI's response in the chat UI and speak it
            displayMessage(data.message, 'ai');
            speakAIResponse(data.message); // Use the response from GPT as the message to speak
        })
        .catch(error => {
            console.error('Error:', error);
            let errorMessage = 'Sorry, something went wrong with fetching the AI response.';
            displayMessage(errorMessage, 'ai'); // Display fallback message in chat UI
            speakAIResponse(errorMessage); // Fallback speech
        });
    }
    

    function populateVoices() {
        let voices = speechSynthesis.getVoices();
        if (voices.length === 0) {
            speechSynthesis.addEventListener('voiceschanged', function() {
                voices = speechSynthesis.getVoices();
                console.log('Voices loaded');
            });
        }
    }
    
    speechSynthesis.onvoiceschanged = function() {
        populateVoices(); // Your function to populate voice options based on available voices
    };
    

    function speakAIResponse(message) {
        let utterance = new SpeechSynthesisUtterance(message);
        let selectedVoiceGender = voiceGenderSelect.value;
        
        // Assuming you've fetched voices and filtered them based on gender
        let voices = speechSynthesis.getVoices();
        utterance.voice = voices.find(voice => voice.gender === selectedVoiceGender); // Simplified, adjust as needed

        utterance.onstart = function() {
            startTalking(); // Start the mouth blinking when speech starts
        };
        utterance.onend = function() {
            stopTalking(); // Stop the mouth blinking when speech ends
        };
    
        speechSynthesis.speak(utterance);
    }

    // Example to start the talking effect
    function startTalking() {
        const mouthOverlay = document.getElementById('mouth-overlay');
        mouthOverlay.style.display = 'block'; // Make the mouth visible
        mouthOverlay.style.animation = 'blink .5s linear infinite'; // Start blinking    
    }

    // Example to stop the talking effect
    function stopTalking() {
        const mouthOverlay = document.getElementById('mouth-overlay');
        mouthOverlay.style.animation = 'none'; // Stop blinking
        mouthOverlay.style.display = 'none'; // Optionally hide the overlay again
    }

    document.querySelectorAll('.feedback-buttons .upvote').forEach(button => {
        button.addEventListener('click', function() {
            sendFeedback('positive');
        });
    });
    
    document.querySelectorAll('.feedback-buttons .downvote').forEach(button => {
        button.addEventListener('click', function() {
            sendFeedback('negative');
        });
    });
    
    function sendFeedback(feedbackType) {
        // Assuming you're sending feedback for the most recent message
        // You might need to adjust this depending on how you're tracking message IDs
        // For simplicity, this example does not include message ID tracking
    
        fetch('/send_feedback', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                messageId: "latestMessageId", // Replace "latestMessageId" with actual message ID tracking logic
                feedback: feedbackType,
            }),
        })
        .then(response => response.json())
        .then(data => {
            console.log('Feedback sent:', data);
            // Handle any follow-up UI changes here (e.g., disable feedback buttons)
        })
        .catch(error => {
            console.error('Error sending feedback:', error);
        });
    }

    function downloadChatSummary() {
        console.log("Attempting to download chat summary...");
        fetch('/download_chat_summary')
            .then(response => response.blob()) // Convert the response to a blob
            .then(blob => {
                // Create a new URL for the blob
                const url = window.URL.createObjectURL(blob);
                // Create a new anchor element (`<a>`) for the download
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                // Set the download filename
                a.download = 'chat_summary.txt';
                // Append the anchor to the document
                document.body.appendChild(a);
                // Trigger the download
                a.click();
                // Clean up by revoking the object URL and removing the anchor
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            })
            .catch(error => console.error('Download error:', error));
    }
   
    function downloadVoiceChatSummary() {
        console.log("Attempting to download voice chat summary...");
        fetch('/download_chat_summary')
            .then(response => response.blob()) // Convert the response to a blob
            .then(blob => {
                // Create a new URL for the blob
                const url = window.URL.createObjectURL(blob);
                // Create a new anchor element (`<a>`) for the download
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                // Set the download filename
                a.download = 'chat_summary.txt';
                // Append the anchor to the document
                document.body.appendChild(a);
                // Trigger the download
                a.click();
                // Clean up by revoking the object URL and removing the anchor
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            })
            .catch(error => console.error('Download error:', error));
    }

});
