import os
import tkinter as tk

class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack()
        self.create_widgets()

    def create_widgets(self):
        self.command_label = tk.Label(self, text="Enter command:")
        self.command_label.pack()
        self.command_entry = tk.Entry(self)
        self.command_entry.pack()
        self.run_button = tk.Button(self, text="Run", command=self.run_command)
        self.run_button.pack()
        self.output_text = tk.Text(self, height=10, width=50)
        self.output_text.pack()

    def run_command(self):
        command = self.command_entry.get()
        output = os.popen(command).read()
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", output)

root = tk.Tk()
app = Application(master=root)
app.mainloop()
