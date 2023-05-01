# CSharp .net

## SQLInjection2
The program uses an SQL query to fetch the data for the given username from the database. The SQL query in the program is vulnerable to SQL injection attacks because it uses string concatenation to include the user input directly into the query. You can try " ' OR 1=1 --" to bypass the username check and fetch all the data from the database.

## Command Injection
The following vulnerability is hosted locally as an example, but to run the code, you should run it with dotnet build, dotnet run. Since it's a .NET web build, it will give you your locally used localhost URL.
1. To execute a command, you can use the URL "http://localhost:5203/execute?command=ipconfig" (change the port with your own).
2. You can also try another command "http://localhost:5203/execute?command=dir" (change the port).

## CSRF
The code has these vulnerabilities:
1. The code is vulnerable to command injection, where user input is executed in a shell without proper validation.
2. The code lacks protection against Cross-Site Request Forgery (CSRF) attacks.
3. The code does not validate user input, which can lead to unexpected behavior and security bypass.

The CSRF vulnerability in the code allows an attacker to submit a POST request to execute a malicious command on behalf of a victim user without their consent. You can test this by going to the following URL "http://localhost:5045/account" (change port) here you can click the button and a post request is sent with a predefined command in this case it's not harmful (echo command).

## Bufferoverflow
This program creates a buffer overflow vulnerability by copying a user-inputted string into a small buffer, which can cause unexpected behavior or even security issues. Try writing your name longer than 2 letters and the buffer overflow will happen.

## Authentication
This is to showcase a site vulnerable to authentication:
1. You can first try reaching: "http://localhost:5000/home" this will say "You must be authenticated to access this page."
2. You can then try to reach "http://localhost:5000/login?username=admin" this will say "Login successful" since there are no passwords on the site.
3. Finally, access the sensitive information by sending the "authenticated" header. This can be done with the bash command:
curl http://localhost:5000/home -H "authenticated: authenticated"
or Powershell
Invoke-WebRequest -Uri "http://localhost:5000/home" -Headers @{ "authenticated" = "authenticated" }

## Direct Object Reference
Direct object reference is a type of security vulnerability where an attacker can access sensitive information or functionality by manipulating a reference to an internal object, such as an ID, without proper authorization. To test the vulnerability:
1. Go to "http://localhost:5110/orders?username=Alice&password=1234&id=ALFKI" to view orders for customer with ID ALFKI.
2. Try to access the orders for a different customer by changing the id parameter to a value that exists in the orders table for a different customer, for example, http://"localhost:5110/orders?username=Alice&password=1234&id=ANATR."


# Python

## Arbitrary Code Execution
Sets up a server listening on port 8080 for incoming connections. Deserializes incoming data using `pickle`. If deserialization is successful, executes the object using the `system` function. Allows arbitrary code execution on the server.

## Best Practice
The code prompts the user for the name of a file to delete. The program then attempts to delete the file using the `os.remove` function. However, there are no security checks or restrictions in place, so any file can be deleted. This makes the program vulnerable to unintended deletions or deletions of important system files.

## Buffer Overflow
The code creates an empty list called `a` and enters an infinite loop. Within the loop, the code appends a string of 1,000,000 characters to the list `a`, potentially causing a buffer overflow. The function `maybe_buffer_overflow()` is called when the script is run. Since the loop is infinite, the code will continue to consume memory until the system runs out of resources. It's called `maybe_buffer_overflow` since Python usually protects against it.

## Command Injection
The application allows the user to enter a command to be executed. The command is executed using the `os.popen` function, which can be used to execute arbitrary commands on the system. The output of the command is displayed in a text box in the GUI. This is a security vulnerability because it allows an attacker to execute any command they want on the system running the application. You can try running "DIR" in the text box, and you will see the file directory being shown.

## SQL Injection 2
When the user submits a username, the `unsafe_function` is called, which retrieves data from the `users` table using a SQL query constructed with user input, creating a SQL injection vulnerability. The retrieved data is then displayed in a text field in the GUI. To test the vulnerability, you can, for example, write this in the comment box:
"charlie' OR 1=1 --" to get all users, or "' UNION SELECT * FROM users WHERE id=2--" to get user number 2 (Bob).

## XSS
This code is vulnerable to an XSS attack through the feedback endpoint because it does not sanitize or escape the feedback text before displaying it in the response. An attacker could inject malicious script code into the feedback parameter, which would be executed by the victim's browser when the response is displayed.

# JAVA

## SQL_Injection2
The `java` directory includes a `\lib` library that should contain the latest SQLite JDBC release to create a database in-memory. If it's not present, it can be found here:
[https://github.com/xerial/sqlite-jdbc/releases](https://github.com/xerial/sqlite-jdbc/releases)
This should lead to the same path found in `.vscode/settings.json`.

### Testing the vulnerability
Try writing `"' OR 1=1 --"` in the field. If the application is vulnerable to SQL injection, this input will return all records in the database instead of just the record with the username entered.

## XSS2
For ease of use, the XSS application `XSS2.java` doesn't actually run in the browser, but it uses HTML code. You can write normal text and see it displayed, or you can test the vulnerability with the following injections:
`<script>alert("XSS")</script>`
`<img src="nonexistent-image.jpg" onerror="alert('XSS')">`

## CSRF2
The following code is just an example of how `CSRF1` would work in a real-world scenario. The user visits the "Attacker Site" and clicks the "Click me for free stuff!" button. This button has an action listener that simulates the CSRF attack by directly calling the same action that transfers funds (shown by the "Funds transferred!" message).

## Remote_code
This code has the following:

1. Deserialization (lines 9-12): Untrusted data is deserialized, allowing attackers to craft malicious objects and execute arbitrary code.
2. Runtime.exec() (lines 20-22): Shell commands are executed, enabling attackers to inject commands and perform remote code execution (RCE).
3. Reflection (lines 25-39): Java reflection creates class instances, posing security risks if attackers control the class name or behavior, leading to arbitrary code execution.

## SSRF
This code performs a simple HTTP GET request to a user-specified URL and prints the response code and body. For example, try writing `https://www.example.com` when prompted.




# JS/TS Project

## SQL Injection 2
This app is run with React in the folder `sql_injection2`. The code is vulnerable to SQL injection because it constructs the query string using user input without proper sanitization. If the attacker entered "'; DROP TABLE users; --," the resulting query would be:
"SELECT * FROM users WHERE username=''; DROP TABLE users; --'". This would show all users on the system, but an attacker could input any malicious code into the username field to execute unintended SQL commands.

## XSS
This file contains 3 vulnerabilities:
1. Unsanitized user input: Enter the following message in the input field and click the "Display Message" button: `<script>alert('XSS')</script>` or `<img src="nonexistent-image.jpg" onerror="alert('XSS')">`
2. Injected script in URL: Add the following query string to the URL: `?param=<script>alert('XSS')</script>`
3. The `displayImage` method is vulnerable to cross-site scripting (XSS) attacks because it uses unsanitized user input to generate HTML content. This allows an attacker to inject malicious code, such as a script tag, into the generated HTML and execute it in the context of the web page.

## RCE - Remote Code Execution
This code sets up a web server using the Express framework for Node.js. The server listens on port 3000 for incoming connections.
1. Remote Code Execution (RCE): The `/api/execute` endpoint takes user input and passes it to the `eval()` function, allowing attackers to execute arbitrary code on the server.
2. Code Injection: The `/api/add` endpoint allows users to input values for x and y without validating or sanitizing them, which could lead to code injection attacks.
3. Lack of Input Validation: The `/api/add` endpoint does not validate user input, which could allow attackers to send malicious input to the server.
4. Implicit Type Conversion: The '+ operator' used in the `/api/add` endpoint can cause implicit type conversion, which could lead to unexpected results if users send non-numeric input.

## SSRF Server-Side Request Forgery (SSRF) Attacks
The server is vulnerable to Server-Side Request Forgery (SSRF) attacks. An attacker can manipulate the URL parameter in the HTML form to make the server perform requests to internal or external networks, and retrieve data that they're not authorized to access. An attacker can also craft the URL to exploit vulnerabilities in internal servers.

## DOM
The JavaScript code has three vulnerabilities.
1. Unsafe Input Handling: The `greet()` function retrieves user input from a text field and inserts it directly into the HTML document, without proper sanitization or validation. An attacker could enter a script as their name, which would then be executed by the page when the `greet()` function is called.
2. Cross-Site Scripting (XSS): The `searchQuery` variable retrieves a query parameter from the URL and inserts it directly into the HTML document. An attacker could insert a script into the search query parameter of the URL, which would then be executed by the page when it is loaded.
3. DOM-Based Redirect: The `redirectUrl` variable retrieves a query parameter from the URL and uses it to redirect the user to another page. An attacker could create a URL that includes a malicious redirect and then convince the user to click on it, leading them to the attacker's website.

# C/C++

## UAF (Use-After-Free)
The vulnerability in this code is that it attempts to use memory that has already been freed, which can lead to undefined behavior or crashes.

## Race Conditions
Since the two threads are accessing and modifying the same global variable concurrently, there is a possibility of a race condition occurring where the final value of `global_var` is different from what is expected.

## Buffer Overflow
This program demonstrates how a buffer overflow can occur when the size of the input data exceeds the size of the buffer allocated to store it. An attacker can exploit this vulnerability to overwrite data in memory and potentially execute malicious code.

## Null Pointer
The code has two vulnerabilities: Null Pointer Dereference Vulnerability and Uninitialized Pointer Vulnerability. To exploit these vulnerabilities, an attacker could pass a null pointer or uninitialized pointer to `func2()`, or try to dereference a null pointer in `func1()`. This could potentially crash the program or allow the attacker to execute malicious code.

## Memory Leaks
If an attacker can run this code on a system they control, they can consume all available memory on that system, which can cause other processes to crash or become unresponsive.

## Format String Vulnerability
In summary, the vulnerability in this code is the lack of input validation in the `vuln_func` function, which could allow an attacker to execute arbitrary code or leak sensitive information.

## Credentials Hardcoded
The program is vulnerable to several security issues:
1. Lack of encryption: The username and password are stored in plaintext in the program.
2. Hardcoded credentials: The username and password are hardcoded into the program and cannot be changed easily.
3. Lack of input validation: The program accepts user input for username and password but does not validate or sanitize the input, which can lead to buffer overflow attacks.
4. Insecure comparison: The program uses `strcmp()` to compare the input username and password with the hardcoded values. This function is vulnerable to timing attacks that can be used to guess the values of the hardcoded credentials.
