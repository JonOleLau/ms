using System;
using System.Data.SqlClient;

class Program
{
    static void Main()
    {
        Console.Write("Enter a username: ");
        string userInput = Console.ReadLine();

        string connectionString = "Server=myServer;Database=myDb;User Id=myUsername;Password=myPassword;";
        string query = $"SELECT * FROM users WHERE username='{userInput}'";

        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            connection.Open();
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                using (SqlDataReader reader = command.ExecuteReader())
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
