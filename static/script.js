let token = localStorage.getItem('token') || ''; // Retrieve token from localStorage on page load or set to an empty string

async function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch('/api/token', { // Ensure the endpoint matches your backend route
            method: 'POST',
            headers: {
                'Content-Type': 'application/json', // Use JSON for the request
            },
            body: JSON.stringify({ username, password }), // Send credentials in JSON format
        });

        const data = await response.json();
        console.log(data); // Debugging log to check the response

        if (response.ok) {
            token = data.access_token; // Store the token in the variable
            localStorage.setItem('token', token); // Store the token in localStorage for persistence

            // Assuming the backend response includes the user role, check the role
            if (data.role_id === 1) { // Admin role
                console.log('Admin logged in');
                document.getElementById('loginForm').style.display = 'none';
                document.getElementById('adminPanel').style.display = 'block';
            } else if (data.role_id === 2) { // User role
                console.log('User logged in');
                showMessage('loginMessage', 'User login successful', 'success');
                setTimeout(() => {
                    displayUserDashboard(); // Show user dashboard after successful login
                });
            }
        } else {
            showMessage('loginMessage', data.detail || 'Login failed. Please try again.', 'error');
        }
    } catch (error) {
        showMessage('loginMessage', 'Login failed. Please try again.', 'error');
    }
}

// New function to display user dashboard on the same page
function displayUserDashboard() {
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('userDashboard').style.display = 'block'; // Show user dashboard
    document.getElementById('welcomeMessage').innerHTML = `Hello, <span style="color: blue; font-weight: bold;">${username}</span>!`;
    console.log(username);
}

async function createUser() {
    const username = document.getElementById('newUsername').value;
    const password = document.getElementById('newPassword').value;
    const email = document.getElementById('email').value;

    if (!token) {
        showMessage('createMessage', 'Please log in first.', 'error');
        return;
    }

    // Validate email and password
    if (!validateEmail(email)) {
        showMessage('createMessage', 'Invalid email format.', 'error');
        return;
    }

    if (!validatePassword(password)) {
        showMessage('createMessage', 'Password must be at least 8 characters long and contain at least one number and one uppercase letter.', 'error');
        return;
    }

    try {
        const response = await fetch('/api/users/create', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify({
                username,
                password,
                email,
                role_id: 2, // Assuming '2' is the user role ID
            }),
        });

        const data = await response.json();

        if (response.ok) {
            showMessage('createMessage', 'User created successfully', 'success');
            // Clear the input fields after successful creation
            document.getElementById('newUsername').value = '';
            document.getElementById('newPassword').value = '';
            document.getElementById('email').value = '';
        } else {
            // Check for specific error messages
            if (data.detail === "Access denied. Only admins can create users.") {
                // Redirect to dashboard if access is denied
                window.location.href = 'dashboard.html';
            } else {
                showMessage('createMessage', data.detail || 'Failed to create user. Please try again.', 'error');
            }
        }
    } catch (error) {
        showMessage('createMessage', 'Failed to create user. Please try again.', 'error');
    }
}

function logout() {
    token = ''; // Clear token
    localStorage.removeItem('token'); // Remove token from localStorage
    document.getElementById('adminPanel').style.display = 'none';
    document.getElementById('userDashboard').style.display = 'none'; // Hide the user dashboard
    document.getElementById('loginForm').style.display = 'block';
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
}

function showMessage(elementId, message, type) {
    const element = document.getElementById(elementId);
    element.textContent = message;
    element.className = type; // Assuming you have CSS classes for success/error messages
    element.style.display = 'block';
    setTimeout(() => {
        element.style.display = 'none';
    }, 3000);
}

// Email validation function
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/; // Basic email regex
    return re.test(String(email).toLowerCase());
}

// Password validation function
function validatePassword(password) {
    // Password must be at least 8 characters long, contain at least one number and one uppercase letter
    const re = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/; 
    return re.test(password);
}
