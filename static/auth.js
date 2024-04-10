document.getElementById('signout-button').addEventListener('click', function() {
    fetch('/signout', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        credentials: 'same-origin' // Ensure cookies are sent with the request
    })
    .then(response => {
        if (response.ok) {
            // Handle successful sign out (e.g., redirect or refresh the page)
            window.location.href = '/';
        } else {
            alert('Sign out failed.');
        }
    })
    .catch(error => console.error('Error:', error));
});

