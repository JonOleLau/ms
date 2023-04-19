<!DOCTYPE html>
<html>
<head>
    <title>DOM-based Vulnerabilities Example</title>
</head>
<body>
    <h1>Welcome to our website!</h1>
    <p>Please enter your name:</p>
    <input type="text" id="name-input">
    <button onclick="greet()">Submit</button>

    <script>
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
    </script>

    <div id="greeting"></div>
    <div id="search-results"></div>
</body>
</html>