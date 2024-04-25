document.addEventListener('DOMContentLoaded', function() {
    const chatModal = document.getElementById('chat-modal');
    const chatHistModal = document.getElementById('chat-history-modal')
    const closeButton = document.getElementById('close-chat');
    const closeHistoryButton = document.getElementById('close-chat-history');
    const sendButton = document.getElementById('send-btn');
    const userInput = document.getElementById('user-input');
    const chatBox = document.getElementById('chat-box');
    const recordButton = document.getElementById('record-voice');
    const voiceModal = document.getElementById('voice-chat-modal');
    const closeVoiceChatButton = document.getElementById('close-voice-chat');
    //const voiceGenderSelect = document.getElementById('voice-gender-select'); // Dropdown for selecting voice gender

    let isRecording = false;
    let recognition;


    document.getElementById('download-chat').addEventListener('click', downloadChatSummary);
    document.getElementById('download-voice-chat').addEventListener('click', downloadVoiceChatSummary);

    document.getElementById('emailForm').addEventListener('submit', function(e) {
        e.preventDefault(); // Prevent the default form submission
        sendChatSummaryEmail();
    });

    document.getElementById('email-transcript').addEventListener('click', function() {
        var email = document.getElementById('email-input').value;  // Assuming you have an input with id 'emailTextbox'
        console.log("emailis:", email)
        if(email) {
            // Prepare the data to be sent
            var data = { email: email };
            
            fetch('/email_chat_transcript', {  // Change the endpoint as needed
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            })
            .then(response => response.json())
            .then(data => {
                alert("Email sent successfully!");
            })
            .catch((error) => {
                console.error('Error:', error);
                alert("Failed to send email.");
            });
        } else {
            alert("Please enter an email address.");
        }
    });
    

    document.getElementById('emailFormVoice').addEventListener('submit', function(e) {
        e.preventDefault(); // Prevent the default form submission
        sendVoiceChatSummaryEmail();
    });
    
    
    function sendChatSummaryEmail() {
        const email = document.getElementById('email-input').value;
        console.log(email)
    
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

    function sendVoiceChatSummaryEmail() {
        const email = document.getElementById('voice-email-input').value;
        console.log(email)
    
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
    document.getElementById('view-past-chats').addEventListener('click', function(event) {
        event.preventDefault();
        chatHistModal.style.display = 'block';
        fetchChatHistory();
    });
    
    function fetchChatHistory() {
        const email = getLoggedInUserEmail(); // Assuming you have this function from your initial code
        fetch(`/get_chats_for_user`)
        .then(response => response.json())
        .then(data => {
            console.log(data);
            populateChatList(data);
        })
        .catch(error => console.error('Error:', error));
    }

    function populateChatList(chats) {
        const chatList = document.getElementById('chat-list');
        chatList.innerHTML = ''; // Clear existing chat history
    
        chats.forEach((chat, index) => {
            const chatDiv = document.createElement('div');
            chatDiv.classList.add('chat-session');
            chatDiv.setAttribute('data-index', index); // Set a data attribute to identify the chat
    
            const previewLength = 50;
            let chatPreview = chat.length > previewLength ? chat.substring(0, previewLength) + "..." : chat;
            chatDiv.innerHTML = chatPreview.replace(/\n/g, '<br>');
    
            chatDiv.addEventListener('click', () => displayFullChat(chat)); // Add click event to display full chat
    
            chatList.appendChild(chatDiv);
        });
    }

    function displayFullChat(chatContent) {
        const chatDisplay = document.getElementById('chat-conversation');
        chatDisplay.innerHTML = ''; // Clear previous content
    
        // Split the chatContent by newline and iterate through each line
        chatContent.split('\n').forEach(line => {
            const messageDiv = document.createElement('div');
            
            // Check if the line starts with "User:" or "Assistant:" and style accordingly
            if (line.startsWith('User:')) {
                messageDiv.classList.add('user-message');
                messageDiv.innerHTML = line.substring(5); // Remove "User:" from the display text
            } else if (line.startsWith('Assistant:') || line.startsWith('Ai:') || line.startsWith('System:')) {
                messageDiv.classList.add('ai-message');
                messageDiv.innerHTML = line.substring(10); // Remove "Assistant:" from the display text
            } else {
                // For lines that don't start with "User:" or "Assistant:", treat them as continuation of the previous message
                messageDiv.innerHTML = line;
            }
    
            chatDisplay.appendChild(messageDiv);
        });
    }
    
    
    // function displayFullChat(chatContent) {
    //     const chatDisplay = document.getElementById('chat-conversation');
    //     chatDisplay.innerHTML = chatContent.replace(/\n/g, '<br>'); // Replace line breaks with HTML for display
    // }

    closeHistoryButton.addEventListener('click', function() {
        chatHistModal.style.display = 'none';
    });
    
    
    // Open text chat modal
    document.getElementById('open-chat').addEventListener('click', function(event) {
        event.preventDefault();
        chatModal.style.display = 'block';
        displayMessage("Hi! I am your AI assistant! I can help with your mental health. Let us have a conversation! If you are facing a mental health emergency, please call 911 immediately.", 'ai');
    });

    // Close text chat modal
    closeButton.addEventListener('click', function() {
        // Confirm with the user
        var userWantsToSave = confirm("Do you want to save your chat before closing?");

        if (userWantsToSave) {            
            fetch('/save', {
                method: 'POST', // or 'PUT'
                // headers: {
                //     'Content-Type': 'application/json',
                // },
                // body: JSON.stringify(chatData),
            })
            .then(response => response.json())
            .then(data => {
                console.log('Success:', data);
                chatModal.style.display = 'none';
            })
            .catch((error) => {
                console.error('Error:', error);
            });
        } else {
            // User does not want to save the chat or canceled the dialog
            chatModal.style.display = 'none';
        }
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
        speakAIResponse("Hi! I am your AI assistant! I can help with your mental health. Let us have a conversation! If you are facing a mental health emergency, please call 911 immediately");
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
        // let selectedVoiceGender = voiceGenderSelect.value;
        
        // Assuming you've fetched voices and filtered them based on gender
        let voices = speechSynthesis.getVoices();
        // utterance.voice = voices.find(voice => voice.gender === selectedVoiceGender); // Simplified, adjust as needed

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

    // document.querySelectorAll('.feedback-buttons .upvote').forEach(button => {
    //     button.addEventListener('click', function() {
    //         sendFeedback('positive');
    //     });
    // });
    
    // document.querySelectorAll('.feedback-buttons .downvote').forEach(button => {
    //     button.addEventListener('click', function() {
    //         sendFeedback('negative');
    //     });
    // });
    
    // function sendFeedback(feedbackType) {
    //     // Assuming you're sending feedback for the most recent message
    //     // You might need to adjust this depending on how you're tracking message IDs
    //     // For simplicity, this example does not include message ID tracking
    
    //     fetch('/send_feedback', {
    //         method: 'POST',
    //         headers: {
    //             'Content-Type': 'application/json',
    //         },
    //         body: JSON.stringify({
    //             messageId: "latestMessageId", // Replace "latestMessageId" with actual message ID tracking logic
    //             feedback: feedbackType,
    //         }),
    //     })
    //     .then(response => response.json())
    //     .then(data => {
    //         console.log('Feedback sent:', data);
    //         // Handle any follow-up UI changes here (e.g., disable feedback buttons)
    //     })
    //     .catch(error => {
    //         console.error('Error sending feedback:', error);
    //     });
    // }
    
    // var downvoteButton = document.getElementById('downvoteButton'); // Ensure this ID matches your downvote button's ID

    // downvoteButton.addEventListener('click', function() {
    //     // It seems you're trying to get the last user message. Make sure this aligns with your actual UI structure.
    //     const message = this.previousElementSibling ? this.previousElementSibling.textContent : "";
    
    //     fetch('/downvote', {
    //         method: 'POST',
    //         headers: {
    //             'Content-Type': 'application/json',
    //         },
    //         // The body might need adjustment depending on how you're identifying messages on the server side.
    //         body: JSON.stringify({ message: message.trim() }),
    //     })
    //     .then(response => response.json())
    //     .then(data => {
    //         // Use the displayMessage function to add the new message to the UI.
    //         displayMessage(data.message, 'ai');
    //     })
    //     .catch(error => {
    //         console.error('Error:', error);
    //     });
    // });

    var downvoteButton = document.getElementById('downvoteButton'); // Ensure this ID matches your downvote button's ID

    downvoteButton.addEventListener('click', function() {
        // Assuming the last message is always from the AI when the downvote is clicked
        // Find the last AI message element in the chatBox and remove it
        const aiMessages = document.querySelectorAll('.ai-message');
        if (aiMessages.length > 0) {
            const lastAiMessage = aiMessages[aiMessages.length - 1];
            chatBox.removeChild(lastAiMessage);
        }

        fetch('/downvote', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({}), // Adjust as needed for your downvote endpoint's requirements
        })
        .then(response => response.json())
        .then(data => {
            displayMessage(data.message, 'ai'); // Display the new AI response
        })
        .catch(error => {
            console.error('Error:', error);
        });
    });

    
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
