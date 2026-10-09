from flask import Flask, jsonify

app = Flask(__name__)
NOTES: list[dict] = []


@app.get("/")
def index():
    return "Team notes"


@app.get("/notes")
def list_notes():
    return jsonify(NOTES)
