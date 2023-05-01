// Import necessary modules
import mysql from 'mysql';

// Set up database connection
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'test_db'
});

// Function to handle user login
function login(username, password) {
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  connection.query(sql, (error, results) => {
    if (error) throw error;
    if (results.length === 1) {
      console.log(`Welcome, ${results[0].username}!`);
    } else {
      console.log('Invalid username or password.');
    }
  });
}

// Function to handle user registration
function register(username, password, email) {
  const sql = `INSERT INTO users (username, password, email) VALUES ('${username}', '${password}', '${email}')`;
  connection.query(sql, (error, results) => {
    if (error) throw error;
    console.log('User registered successfully!');
  });
}

// Sample usage
login('admin', "1' OR '1'='1");
register("testuser", "password123", "testuser@example.com', ''); DROP TABLE users; --");