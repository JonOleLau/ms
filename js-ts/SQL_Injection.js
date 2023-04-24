const mysql = require('mysql2/promise');

async function setupDatabase() {
  const connection = await mysql.createConnection({
    user: 'root',
    password: '',
    database: 'test_db',
    host: 'localhost',
    port: 3306,
    typeCast: function(field, next) {
      if (field.type === 'VAR_STRING') {
        return field.string();
      }
      return next();
    },
    multipleStatements: true
  });
  await connection.query('CREATE DATABASE IF NOT EXISTS test_db');
  await connection.query('USE test_db');
  await connection.query('CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(255), password VARCHAR(255), email VARCHAR(255))');
  await connection.query(`INSERT INTO users (username, password, email) VALUES ('admin', 'password', 'admin@example.com')`);
  return connection;
}

// Function to handle user login
async function login(username, password) {
  const connection = await setupDatabase();
  const [rows] = await connection.execute(`SELECT * FROM users WHERE username = ? AND password = ?`, [username, password]);
  if (rows.length === 1) {
    console.log(`Welcome, ${rows[0].username}!`);
  } else {
    console.log('Invalid username or password.');
  }
  await connection.end();
}

// Function to handle user registration
async function register(username, password, email) {
  const connection = await setupDatabase();
  const [rows] = await connection.execute(`INSERT INTO users (username, password, email) VALUES (?, ?, ?)`, [username, password, email]);
  console.log('User registered successfully!');
  await connection.end();
}

// Sample usage
login('admin', 'password');
register('testuser', 'password123', 'testuser@example.com');
login('testuser', 'password123');
