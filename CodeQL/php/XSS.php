<!DOCTYPE html>
<html>
<head>
    <title>XSS Vulnerable Page</title>
</head>
<body>
    <h1>Welcome to our site!</h1>
    <form action="" method="POST">
        <label for="name">Name:</label>
        <input type="text" id="name" name="name"><br><br>
        <label for="email">Email:</label>
        <input type="text" id="email" name="email"><br><br>
        <input type="submit" name="submit" value="Submit">
    </form>

    <?php
        $name = $_POST["name"];
        $email = $_POST["email"];
        echo "<h2>Thanks for submitting your info, $name!</h2>";
        echo "<p>Your email is: $email</p>";
    ?>

    <script>
        var userInput = prompt("What is your favorite color?");
        document.write("<h2>Your favorite color is: " + userInput + "</h2>");
    </script>
</body>
</html>