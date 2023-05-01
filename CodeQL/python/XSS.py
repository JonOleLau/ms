from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/submit", methods=["POST"])
def submit():
    message = request.form["message"]
    return render_template("output.html", message=message)

@app.route("/feedback")
def feedback():
    feedback_text = request.args.get("feedback")
    return f"<h1>Feedback Received:</h1><p>{feedback_text}</p>"

if __name__ == "__main__":
    app.run(debug=True)
