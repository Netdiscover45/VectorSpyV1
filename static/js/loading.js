
const messages = [
    "Initializing Security Modules...",
    "Loading Assessment Engine...",
    "Preparing Security Scanner...",
    "Initializing Risk Analysis...",
    "System Ready..."
];

let index = 0;

const status = document.getElementById("status");

const messageInterval = setInterval(function () {

    index++;

    if (index < messages.length) {
        status.textContent = messages[index];
    }

}, 900);


// Redirect after 5 seconds

setTimeout(function () {

    clearInterval(messageInterval);

    window.location.href = "/welcome";

}, 5000);