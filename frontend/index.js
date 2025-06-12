// Handle login form submission
document.getElementById("login-form").addEventListener("submit", function (event) {
    event.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    // Send login request to the backend
    fetch("http://127.0.0.1:5000/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            username: username,
            password: password,
        }),
    })
        .then(response => response.json())
        .then(data => {
            console.log(data); // Check the response to debug
            // Check if login was successful (update this to match your API response)
            if (data.message && data.message === "Login successful") {
                // Hide login section and show dashboard
                document.getElementById("login-section").style.display = "none";
                document.getElementById("dashboard-section").style.display = "block";

                // Fetch initial emails and update the dashboard
                fetchEmails();
                // Start polling for new emails every minute
                setInterval(fetchEmails, 60000);
            } else {
                alert("Login failed! Please check your credentials.");
            }
        })
        .catch(error => {
            console.error("Error during login:", error);
            alert("Login failed! Please try again later.");
        });
});

// Polling for new emails every minute
setInterval(checkEmails, 60000);

function checkEmails() {
    fetch("http://127.0.0.1:5000/emails")
        .then(response => response.json());
}


// Fetch emails from the backend and update the list
function fetchEmails() {
    fetch("http://127.0.0.1:5000/scanned-emails")
        .then(response => response.json())
        .then(data => updateEmailsList(data));
}
function extractEmail(sender) {
    const regex = /<([^>]+)>/;  // Regular expression to capture the email inside < >
    const match = sender.match(regex);
    return match ? match[1] : null;  // If match is found, return the email, otherwise null
}
function formatEmailDate(dateStr) {
    const date = new Date(dateStr);
    // Format the date and time in a readable format
    return date.toLocaleString('en-US', {
        weekday: 'short',   // Abbreviated weekday
        day: 'numeric',     // Day of the month
        month: 'short',     // Abbreviated month
        year: 'numeric',    // Full year
        hour: 'numeric',    // Hour in 12-hour format
        minute: 'numeric',  // Minutes
        second: 'numeric',  // Seconds
        hour12: true        // 12-hour format
    });
}
function updateEmailsList(emails) {
    let listHtml = '';
    emails.forEach(email => {
        const emailAddress = extractEmail(email.sender);
        const formattedDate = formatEmailDate(email.date);

        let urlStatusHtml = '';
        if (email.url_status && email.url_status.length > 0) {
            email.url_status.forEach(url => {
                urlStatusHtml += `
                    <div class="url-status-item">
                        <span class="url-badge ${url.prediction.toLowerCase()}" data-bs-toggle="tooltip" data-bs-placement="top" title="${url.url}">
                            <span class="prediction">${url.prediction}</span>
                            <span class="url-text">${url.url}</span>
                        </span>
                    </div>
                `;
            });
        }

        listHtml += `
            <div class="email-item rounded shadow p-3 mb-3 ${email.spam_status === 'Spam' ? 'spam' : 'legitimate'}">
                <div class="email-content">
                    <div class="email-field shadow-sm bg-white rounded p-2">
                        <strong>FROM:</strong> <span class="email-value">${email.sender}</span>
                    </div>
                    <div class="email-field shadow-sm bg-white rounded p-2">
                        <strong>EMAIL:</strong> <span class="email-value">${emailAddress || 'Not Provided'}</span>
                    </div>
                    <div class="email-field shadow-sm bg-white rounded p-2">
                        <strong>SUBJECT:</strong> <span class="email-value">${email.subject || 'No Subject'}</span>
                    </div>
                    <div class="email-field shadow-sm bg-white rounded p-2">
                        <strong>TIME:</strong> <span class="email-value">${formattedDate}</span>
                    </div>
                    <div class="email-field shadow-sm bg-white rounded p-2">
                        <strong>STATUS:</strong> <span class="status-value">${email.spam_status.toUpperCase()}</span>
                    </div>
                    ${urlStatusHtml ? `<div class="urls-container mt-2">${urlStatusHtml}</div>` : ''}
                </div>
            </div>
        `;
    });
    document.getElementById("emails-list").innerHTML = listHtml;

    // Initialize tooltips if using Bootstrap
    if (typeof bootstrap !== 'undefined') {
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
}
// Helper function to format date
function formatDate(dateString) {
    if (!dateString) return '';
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Enhanced button event listeners with loading states
document.getElementById("check-spam-btn").addEventListener("click", checkSpam);
document.getElementById("check-url-btn").addEventListener("click", checkUrl);

// Enable buttons when input has content
document.getElementById("message-input").addEventListener("input", function () {
    document.getElementById("check-spam-btn").disabled = !this.value.trim();
});

document.getElementById("url-input").addEventListener("input", function () {
    document.getElementById("check-url-btn").disabled = !this.value.trim();
});

// Also allow Enter key to trigger checks
document.getElementById("message-input").addEventListener("keypress", function (e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        if (!document.getElementById("check-spam-btn").disabled) {
            checkSpam();
        }
    }
});

document.getElementById("url-input").addEventListener("keypress", function (e) {
    if (e.key === 'Enter') {
        e.preventDefault();
        if (!document.getElementById("check-url-btn").disabled) {
            checkUrl();
        }
    }
});

function checkSpam() {
    const message = document.getElementById("message-input").value.trim();
    if (!message) return;

    const btn = document.getElementById("check-spam-btn");
    const originalText = btn.textContent;

    // Show loading state
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Analyzing...';

    // Clear previous result
    document.getElementById("check-result").innerHTML = '<div class="loading-placeholder"></div>';

    fetch("http://127.0.0.1:5000/check-spam", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ message }),
    })
        .then(response => response.json())
        .then(data => {
            displayResult(data);
            document.getElementById("message-input").value = ''; // Reset input
        })
        .catch(error => {
            displayError("Failed to analyze message");
            console.error("Error:", error);
        })
        .finally(() => {
            btn.innerHTML = originalText;
            btn.disabled = true; // Keep disabled until new input
        });
}

function checkUrl() {
    const url = document.getElementById("url-input").value.trim();
    if (!url) return;

    const btn = document.getElementById("check-url-btn");
    const originalText = btn.textContent;

    // Show loading state
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Scanning...';

    // Clear previous result
    document.getElementById("check-result").innerHTML = '<div class="loading-placeholder"></div>';

    fetch("http://127.0.0.1:5000/check-url", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
    })
        .then(response => response.json())
        .then(data => {
            displayResult(data);
            document.getElementById("url-input").value = ''; // Reset input
        })
        .catch(error => {
            displayError("Failed to analyze URL");
            console.error("Error:", error);
        })
        .finally(() => {
            btn.innerHTML = originalText;
            btn.disabled = true; // Keep disabled until new input
        });
}

function displayResult(data) {
    const resultDiv = document.getElementById("check-result");
    let resultClass = '';
    let icon = '';

    if (data.spam_status === 'Spam' || data.prediction === 'phishing') {
        resultClass = 'danger-result';
        icon = '<i class="fas fa-exclamation-triangle"></i>';
    } else if (data.spam_status === 'Not Spam' || data.prediction === 'Legitimate') {
        resultClass = 'success-result';
        icon = '<i class="fas fa-check-circle"></i>';
    } else {
        resultClass = 'warning-result';
        icon = '<i class="fas fa-question-circle"></i>';
    }

    resultDiv.innerHTML = `
        <div class="result-card ${resultClass}">
            <div class="result-icon">${icon}</div>
            <div class="result-content">
                <h5>${(data.spam_status || data.prediction || "UNKNOWN").toUpperCase()}</h5>
                ${data.message ? `<p>${data.message}</p>` : ''}
                ${data.probability ? `<p>Confidence: ${(data.probability * 100).toFixed(2)}%</p>` : ''}
                ${data.url ? `<p>URL: <code>${data.url}</code></p>` : ''}
            </div>
        </div>
    `;
}

function displayError(message) {
    document.getElementById("check-result").innerHTML = `
        <div class="result-card error-result">
            <div class="result-icon"><i class="fas fa-times-circle"></i></div>
            <div class="result-content">
                <h5>Error</h5>
                <p>${message}</p>
            </div>
        </div>
    `;
}

// Initial fetch of emails
fetchEmails();
