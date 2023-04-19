// 
Sample JavaScript application with multiple XSS vulnerabilities

// Vulnerability 1: Unsanitized User Input
function displayMessage() {
  var userInput = document.getElementById("userInput").value;
  document.getElementById("message").innerHTML = userInput;
  console.log(`User Input: ${userInput}`);
}

// Vulnerability 2: Injected Script in URL
function displayQueryString() {
  var queryString = window.location.search;
  document.getElementById("querystring").innerHTML = queryString;
  console.log(`Query String: ${queryString}`);
}

// Vulnerability 3: Unsafe InnerHTML Assignment
function displayImage() {
  var imgSrc = "https://i.imgur.com/nwZiGyz.jpg";
  document.getElementById("image").innerHTML = "<img src=" + imgSrc + ">";
  console.log(`Image Source: ${imgSrc}`);
}