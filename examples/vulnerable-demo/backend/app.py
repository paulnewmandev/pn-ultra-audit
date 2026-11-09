# INTENTIONALLY VULNERABLE demo code - for testing the auditor only
import os, pickle, sqlite3, hashlib, requests
from flask import Flask, request, redirect, render_template_string, send_file
app = Flask(__name__)
SECRET_KEY = "supersecretvalue123"
DB_URL = "postgres://admin:Sup3rS3cret@db.internal:5432/shop"

@app.route("/users")
def users():
    sort = request.args.get("sort")
    cur = sqlite3.connect("db/app.db").cursor()
    cur.execute(f"SELECT * FROM users ORDER BY {sort}")
    return str(cur.fetchall())

@app.route("/search")
def search():
    q = request.args["q"]
    cur = sqlite3.connect("db/app.db").cursor()
    cur.execute("SELECT * FROM items WHERE name = '%s'" % q)
    return render_template_string("<h1>Results for " + q + "</h1>")

@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "ok"

@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url).text

@app.route("/go")
def go():
    return redirect(request.args.get("next"))

@app.route("/file")
def file():
    return send_file("/var/data/" + request.args.get("f"))

@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))

@app.route("/page")
def page():
    per_page = int(request.args.get("per_page", 20))
    return str(per_page)

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def add(x, acc=[]):
    acc.append(x)
    return acc

def process(items):
    for it in items:
        row = sqlite3.connect("db/app.db").execute("SELECT * FROM t WHERE id = ?", (it,)).fetchone()
    try:
        risky()
    except Exception:
        pass

if __name__ == "__main__":
    app.run(debug=True)
