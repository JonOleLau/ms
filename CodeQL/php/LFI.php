<?php
  // index.php

  if(isset($_GET['page'])) {
    $page = $_GET['page'];
  } else {
    $page = 'home';
  }

  include($page . '.php');
?>

<html>
<head>
  <title>My Application</title>
</head>
<body>
  <h1>Welcome to my website</h1>
  <ul>
    <li><a href="?page=home">Home</a></li>
    <li><a href="?page=about">About Us</a></li>
    <li><a href="?page=contact">Contact Us</a></li>
  </ul>
</body>
</html>