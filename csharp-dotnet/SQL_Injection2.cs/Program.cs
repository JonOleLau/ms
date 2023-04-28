using System;
using System.Data.SQLite;

namespace MyApp
{
    class Program
    {
        static void Main(string[] args)
        {
            // create in-memory database and populate with sample data
            using (var connection = new SQLiteConnection("Data Source=:memory:"))
            {
                connection.Open();
                using (var command = new SQLiteCommand(connection))
                {
                    command.CommandText = "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)";
                    command.ExecuteNonQuery();

                    var users = new[]
                    {
                        new {id = 1, username = "alice", email = "alice@example.com"},
                        new {id = 2, username = "bob", email = "bob@example.com"},
                        new {id = 3, username = "charlie", email = "charlie@example.com"}
                    };
                    foreach (var user in users)
                    {
                        command.CommandText = $"INSERT INTO users (id, username, email) VALUES ({user.id}, '{user.username}', '{user.email}')";
                        command.ExecuteNonQuery();
                    }
                }

                // prompt user for input
                Console.WriteLine("Enter a username:");
                var userInput = Console.ReadLine();

                // query database and display results
                using (var command = new SQLiteCommand($"SELECT * FROM users WHERE username='{userInput}'", connection))
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Console.WriteLine($"{reader["username"]}: {reader["email"]}");
                    }
                }
            }
        }
    }
}
