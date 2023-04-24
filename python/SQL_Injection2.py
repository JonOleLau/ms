import sqlite3
import tkinter as tk

class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack()
        self.create_widgets()

        # create database and populate with sample data
        self.create_database()

    def create_widgets(self):
        self.username_label = tk.Label(self, text="Enter a username:")
        self.username_label.pack()
        self.username_entry = tk.Entry(self)
        self.username_entry.pack()
        self.submit_button = tk.Button(self, text="Submit", command=self.get_user_data)
        self.submit_button.pack()
        self.output_text = tk.Text(self, height=10, width=50)
        self.output_text.pack()

    def create_database(self):
        # create database and users table
        connection = sqlite3.connect('example.db')
        cursor = connection.cursor()
        cursor.execute('''CREATE TABLE users
                        (id INTEGER PRIMARY KEY,
                        username TEXT,
                        email TEXT)''')

        # insert sample data
        users = [
            ('1', 'alice', 'alice@example.com'),
            ('2', 'bob', 'bob@example.com'),
            ('3', 'charlie', 'charlie@example.com')
        ]
        cursor.executemany("INSERT INTO users VALUES (?, ?, ?)", users)

        connection.commit()
        connection.close()

    def get_user_data(self):
        username = self.username_entry.get()
        result = self.unsafe_function(username)
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", str(result))

    def unsafe_function(self, user_input):
        connection = sqlite3.connect('example.db')
        cursor = connection.cursor()
        query = f"SELECT * FROM users WHERE username='{user_input}'"
        cursor.execute(query)
        result = cursor.fetchall()
        connection.close()
        return result

root = tk.Tk()
app = Application(master=root)
app.mainloop()
