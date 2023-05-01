// Vulnerability #1: Unsafe Input Handling
function greet() {
    const name = document.getElementById("name-input").value;
    document.getElementById("greeting").textContent = `Hello, ${name}!`;
}

// Vulnerability #2: Cross-Site Scripting (XSS)
const searchQuery = new URLSearchParams(window.location.search).get("q");
document.getElementById("search-results").innerHTML = `Showing results for "${searchQuery}"`;

// Vulnerability #3: DOM-Based Redirect
const redirectUrl = new URLSearchParams(window.location.search).get("redirect");
if (redirectUrl) {
    window.location.href = redirectUrl;
}
