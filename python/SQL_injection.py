import sqlite3

def unsafe_function(user_input):
    connection = sqlite3.connect('example.db')
    cursor = connection.cursor()
    query = f"SELECT * FROM users WHERE username='{user_input}'"
    cursor.execute(query)
    result = cursor.fetchall()
    connection.close()
    return result

user_input = input("Enter a username: ")
print(unsafe_function(user_input))