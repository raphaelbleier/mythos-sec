# Fixture for `scripts/sourcemap --selftest`. Deliberately flawed, never run.
from functools import wraps
import sqlite3

from flask import Flask, redirect, request

app = Flask(__name__)
app.config["DEBUG"] = True
DB_PASSWORD = "sup3rs3cret"


def login_required(fn):
    @wraps(fn)
    def inner(*args, **kwargs):
        return fn(*args, **kwargs)

    return inner


@app.route("/")
def index():
    return "ok"


@app.route("/me")
@login_required
def me():
    return {"me": True}


@app.route("/notes")
def notes():
    term = request.args.get("q", "")
    con = sqlite3.connect("notes.db")
    return {"rows": list(con.execute(f"SELECT body FROM notes WHERE body LIKE '%{term}%'"))}


@app.route("/admin/delete/<int:note_id>", methods=["POST"])
def delete_note(note_id):
    con = sqlite3.connect("notes.db")
    con.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    return {"deleted": note_id}


@app.route("/out")
def out():
    return redirect(request.args.get("next", "/"))
