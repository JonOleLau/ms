import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/run_command', methods=['GET'])
def run_command():
    command = request.args.get('command')
    output = os.popen(command).read()
    return output

if __name__ == '__main__':
    app.run(debug=True)