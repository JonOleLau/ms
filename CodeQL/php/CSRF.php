<?php

if(isset($_POST['username']) && isset($_POST['password'])) {
  // Login code here
}

?>

<html>
<head>
  <title>My Application</title>
</head>
<body>
  <h1>Login</h1>
  <form method="POST" action="login.php">
    <label for="username">Username</label>
    <input type="text" name="username" id="username">

    <label for="password">Password</label>
    <input type="password" name="password" id="password">

    <button type="submit">Login</button>
  </form>

  <h1>Change Password</h1>
  <form method="POST" action="changepassword.php">
    <label for="oldpassword">Old Password</label>
    <input type="password" name="oldpassword" id="oldpassword">

    <label for="newpassword">New Password</label>
    <input type="password" name="newpassword" id="newpassword">

    <button type="submit">Change Password</button>
  </form>
</body>
</html>