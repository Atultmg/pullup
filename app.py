# ===== STEP 1: PUT YOUR TWO SECRETS HERE (the only lines you need to change) =====
SECRET_KEY = "PASTE-YOUR-LONG-KEY-HERE"
TEACHER_CODE = "choose-your-teacher-code"        # teachers must type this to sign up
# =================================================================================

# 1. Bring in the tools we need
import csv                                       # writes CSV files
import hashlib                                   # used to sign QR codes
import hmac                                      # used to sign QR codes
import io                                        # holds files in memory
import os                                        # finds this file's folder
import socket                                    # finds this computer's Wi-Fi address
import sqlite3                                   # talks to the database
import time                                      # gives the current time in seconds
from datetime import datetime, timedelta
from functools import wraps
from zoneinfo import ZoneInfo                    # knows what time it is in Nepal
import qrcode                                    # draws QR codes
from flask import (Flask, render_template, request, redirect, session,
                   send_file, jsonify, Response, abort)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

# 2. Settings
# stop with a clear message if the secret key was not changed yet
if SECRET_KEY.startswith("PASTE"):
    raise SystemExit("Open app.py and replace PASTE-YOUR-LONG-KEY-HERE at the top with your secret key.")

app = Flask(__name__)
# lets Flask see the real public address when it runs behind a tunnel or hosting service
# NEW: x_for=1 also shows the student's real address behind a tunnel (needed for the Wi-Fi check)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_for=1)
app.secret_key = SECRET_KEY                      # keeps login cookies safe
BASE_DIR = os.path.dirname(os.path.abspath(__file__))   # the folder this file lives in
DB = os.path.join(BASE_DIR, "pullup_v2.db")      # the database file, always next to app.py
TIMEZONE = "Asia/Kathmandu"                      # change this if your school is in another country
PORT = 5001
PUBLIC_URL = ""                                  # optional: paste your public address here, like https://abc.trycloudflare.com
QR_SECONDS = 30                                  # the QR on the board changes every 30 seconds
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# the current time in YOUR timezone (hosting servers often use a different one)
def local_now():
    return datetime.now(ZoneInfo(TIMEZONE)).replace(tzinfo=None)

# 3. Database helpers
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    # everyone who uses PULLUP: students and teachers
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            id_number TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    """)
    # one row for every class a teacher starts
    # NEW: in_class_only = the teacher ticked the "in the class" checkbox for this class
    # NEW: wifi_network = the class Wi-Fi network, saved when the class starts
    conn.execute("""
        CREATE TABLE IF NOT EXISTS classes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            teacher_id INTEGER NOT NULL,
            start_time TEXT NOT NULL,
            late_minutes INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            ended_at TEXT,
            in_class_only INTEGER NOT NULL DEFAULT 0,
            wifi_network TEXT
        )
    """)
    # one row for every student who scanned: Present, Late, or Waiting (NEW)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            scanned_at TEXT NOT NULL,
            status TEXT NOT NULL,
            UNIQUE (class_id, user_id)
        )
    """)
    # NEW: if the database was made by the older version, add the two new
    # columns to it instead of deleting it (your accounts and classes stay)
    columns = [row["name"] for row in conn.execute("PRAGMA table_info(classes)").fetchall()]
    if "in_class_only" not in columns:
        conn.execute("ALTER TABLE classes ADD COLUMN in_class_only INTEGER NOT NULL DEFAULT 0")
    if "wifi_network" not in columns:
        conn.execute("ALTER TABLE classes ADD COLUMN wifi_network TEXT")
    conn.commit()
    conn.close()

init_db()

# 4. Login helpers
def current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user

# makes "user" available inside every HTML page
@app.context_processor
def inject_user():
    return {"user": current_user()}

# a guard placed above a route: sends people to /login if they are not logged in
def login_required(role=None):
    def wrapper(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            user = current_user()
            if user is None:
                return redirect("/login?next=" + request.path)
            if role == "Teacher" and user["role"] != "Teacher":
                return render_template("message.html", ok=False, title="Teachers only",
                                       text="Only teachers can open this page."), 403
            return fn(*args, **kwargs)
        return inner
    return wrapper

# only allow redirects to pages inside our own site
def safe_next(target):
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return "/dashboard"

# 5. QR helpers: the code on the board changes, so a screenshot stops working
def make_token(class_id, window):
    message = f"{class_id}:{window}".encode()
    return hmac.new(app.secret_key.encode(), message, hashlib.sha256).hexdigest()[:16]

def token_is_valid(class_id, token):
    window = int(time.time() // QR_SECONDS)
    # accept the current code and the last 3, so about 2 minutes to scan and log in
    for w in (window, window - 1, window - 2, window - 3):
        if hmac.compare_digest(make_token(class_id, w), token):
            return True
    return False

# phones cannot open 127.0.0.1, so the QR must contain this computer's Wi-Fi address
def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))               # nothing is sent, it just picks the Wi-Fi address
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()

# the address students' phones should open (the QR code contains this)
def get_base_url():
    if PUBLIC_URL:
        return PUBLIC_URL.rstrip("/")
    # if the teacher opened PULLUP through a public address, use that same address
    if not request.host.startswith(("127.0.0.1", "localhost")):
        return request.host_url.rstrip("/")
    # otherwise fall back to the local Wi-Fi address (only works on the same Wi-Fi)
    return f"http://{lan_ip()}:{PORT}"

# returns the class only if it belongs to the logged-in teacher
def get_class(class_id):
    user = current_user()
    conn = get_db()
    c = conn.execute("SELECT * FROM classes WHERE id = ? AND teacher_id = ?",
                     (class_id, user["id"])).fetchone()
    conn.close()
    return c

# NEW 5B. "In the class" helpers: is this student on the class Wi-Fi?
# the network part of an address: "192.168.110.25" -> "192.168.110"
def network_of(ip):
    if not ip:
        return ""
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3])
    return ip

# True when the student's phone is on the same Wi-Fi the class was started on
def same_wifi(c):
    if not c["wifi_network"]:
        return False
    ip = request.remote_addr or ""               # the student's phone address
    if ip in ("127.0.0.1", "::1"):               # testing on the Mac itself counts as "here"
        return True
    return network_of(ip) == c["wifi_network"]

# 6. Home, sign up, log in, log out
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        id_number = request.form["id_number"].strip()
        role = request.form["role"]
        password = request.form["password"]
        teacher_code = request.form.get("teacher_code", "").strip()
        if role not in ("Student", "Teacher"):
            role = "Student"
        if role == "Teacher" and teacher_code != TEACHER_CODE:
            return render_template("register.html", error="Wrong teacher code. Ask your school for the code.")
        if len(password) < 4:
            return render_template("register.html", error="Password needs at least 4 characters.")
        conn = get_db()
        try:
            cur = conn.execute(
                "INSERT INTO users (name, role, id_number, password_hash) VALUES (?, ?, ?, ?)",
                (name, role, id_number, generate_password_hash(password)))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="That ID number is already registered. Log in instead.")
        session["user_id"] = cur.lastrowid       # log them in straight away
        session.permanent = True                 # stay logged in on the phone
        conn.close()
        return redirect("/dashboard")
    return render_template("register.html", error=None)

@app.route("/login", methods=["GET", "POST"])
def login():
    next_page = request.values.get("next", "")
    if request.method == "POST":
        who = request.form["who"].strip()            # what they typed: ID number or full name
        password = request.form["password"]

        # find everyone whose ID number matches, or whose name matches (capitals ignored)
        conn = get_db()
        found = conn.execute(
            "SELECT * FROM users WHERE id_number = ? OR LOWER(name) = LOWER(?)",
            (who, who)).fetchall()
        conn.close()

        # keep only the people whose password is also correct
        matches = [u for u in found if check_password_hash(u["password_hash"], password)]

        if len(matches) == 1:
            session["user_id"] = matches[0]["id"]
            session.permanent = True
            return redirect(safe_next(next_page))
        if len(matches) > 1:
            # two people with the same name and the same password: ask for the ID instead
            return render_template("login.html", next_page=next_page,
                                   error="More than one person has that name. Please use your ID number.")
        return render_template("login.html", error="Wrong name, ID number or password.", next_page=next_page)
    return render_template("login.html", error=None, next_page=next_page)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# 7. Sends each person to the right dashboard
@app.route("/dashboard")
@login_required()
def dashboard():
    if current_user()["role"] == "Teacher":
        return redirect("/teacher")
    return redirect("/student")

# 8. Teacher: list of classes and the "start a class" form
@app.route("/teacher")
@login_required("Teacher")
def teacher():
    conn = get_db()
    classes = conn.execute("""
        SELECT c.*,
               COALESCE(SUM(a.status = 'Present'), 0) AS present,
               COALESCE(SUM(a.status = 'Late'), 0) AS late
        FROM classes c
        LEFT JOIN attendance a ON a.class_id = c.id
        WHERE c.teacher_id = ?
        GROUP BY c.id
        ORDER BY c.id DESC
    """, (current_user()["id"],)).fetchall()
    conn.close()
    return render_template("teacher.html", classes=classes)

# 9. Teacher presses "Start class": save it with the start time now
# NEW: also save the checkbox and the class Wi-Fi network
@app.route("/class/start", methods=["POST"])
@login_required("Teacher")
def start_class():
    title = request.form["title"].strip() or "Class"
    late_minutes = int(request.form["late_minutes"])
    in_class_only = 1 if request.form.get("in_class_only") else 0
    # the network students must be on = the teacher's own network.
    # Hosted online, the teacher connects from the classroom, so their
    # address IS the class network. Running on this Mac, the teacher's
    # address is private/local, so use this computer's network as before.
    teacher_ip = request.remote_addr or ""
    if teacher_ip.startswith(("192.168.", "10.", "172.", "127.", "::1")):
        wifi_network = network_of(lan_ip())
    else:
        wifi_network = network_of(teacher_ip)
    now = local_now().strftime(TIME_FORMAT)
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO classes (title, teacher_id, start_time, late_minutes, in_class_only, wifi_network) VALUES (?, ?, ?, ?, ?, ?)",
        (title, current_user()["id"], now, late_minutes, in_class_only, wifi_network))
    conn.commit()
    class_id = cur.lastrowid
    conn.close()
    return redirect(f"/class/{class_id}/board")

# 10. The board page: shows the big QR code for the class
@app.route("/class/<int:class_id>/board")
@login_required("Teacher")
def board(class_id):
    c = get_class(class_id)
    if c is None:
        abort(404)
    start = datetime.strptime(c["start_time"], TIME_FORMAT)
    late_at = (start + timedelta(minutes=c["late_minutes"])).strftime("%H:%M")
    return render_template("board.html", c=c, start_at=start.strftime("%H:%M"), late_at=late_at)

# 11. Draws the current QR image (the board page reloads it every 25 seconds)
@app.route("/class/<int:class_id>/qr.png")
@login_required("Teacher")
def class_qr(class_id):
    if get_class(class_id) is None:
        abort(404)
    window = int(time.time() // QR_SECONDS)
    url = f"{get_base_url()}/checkin/{class_id}/{make_token(class_id, window)}"
    img = qrcode.make(url)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    response = send_file(buffer, mimetype="image/png")
    response.headers["Cache-Control"] = "no-store"
    return response

# 12. Live numbers for the board page (it asks for these every few seconds)
# NEW: the waiting list is sent too, so the board can show Approve/Reject buttons
@app.route("/class/<int:class_id>/live")
@login_required("Teacher")
def live(class_id):
    c = get_class(class_id)
    if c is None:
        abort(404)
    conn = get_db()
    rows = conn.execute("""
        SELECT u.id AS user_id, u.name, a.status, a.scanned_at
        FROM attendance a JOIN users u ON u.id = a.user_id
        WHERE a.class_id = ? ORDER BY a.id DESC
    """, (class_id,)).fetchall()
    conn.close()
    done = [r for r in rows if r["status"] != "Waiting"]
    return jsonify(
        active=bool(c["active"]),
        present=len([r for r in rows if r["status"] == "Present"]),
        late=len([r for r in rows if r["status"] == "Late"]),
        recent=[{"name": r["name"], "status": r["status"], "time": r["scanned_at"][11:16]} for r in done[:6]],
        waiting=[{"name": r["name"], "user_id": r["user_id"], "time": r["scanned_at"][11:16]}
                 for r in rows if r["status"] == "Waiting"],
    )

# 13. Teacher ends the class: the QR stops working
@app.route("/class/<int:class_id>/end", methods=["POST"])
@login_required("Teacher")
def end_class(class_id):
    if get_class(class_id) is None:
        abort(404)
    conn = get_db()
    conn.execute("UPDATE classes SET active = 0, ended_at = ? WHERE id = ?",
                 (local_now().strftime(TIME_FORMAT), class_id))
    conn.commit()
    conn.close()
    return redirect(f"/class/{class_id}/report")

# NEW 14. Teacher approves or rejects a student who is Waiting
@app.route("/class/<int:class_id>/approve/<int:user_id>", methods=["POST"])
@login_required("Teacher")
def approve_student(class_id, user_id):
    c = get_class(class_id)
    if c is None:
        abort(404)
    conn = get_db()
    row = conn.execute("SELECT * FROM attendance WHERE class_id = ? AND user_id = ? AND status = 'Waiting'",
                       (class_id, user_id)).fetchone()
    if row is not None:
        # Present or Late is worked out from when they SCANNED, not when approved,
        # so a student who scanned on time is not punished for a slow approval
        scanned = datetime.strptime(row["scanned_at"], TIME_FORMAT)
        start = datetime.strptime(c["start_time"], TIME_FORMAT)
        minutes_after_start = (scanned - start).total_seconds() / 60
        status = "Late" if minutes_after_start > c["late_minutes"] else "Present"
        conn.execute("UPDATE attendance SET status = ? WHERE id = ?", (status, row["id"]))
        conn.commit()
    conn.close()
    return redirect(f"/class/{class_id}/board")

@app.route("/class/<int:class_id>/reject/<int:user_id>", methods=["POST"])
@login_required("Teacher")
def reject_student(class_id, user_id):
    if get_class(class_id) is None:
        abort(404)
    conn = get_db()
    # rejecting removes the waiting row, so the student does not appear in the report
    conn.execute("DELETE FROM attendance WHERE class_id = ? AND user_id = ? AND status = 'Waiting'",
                 (class_id, user_id))
    conn.commit()
    conn.close()
    return redirect(f"/class/{class_id}/board")

# 15. Helper: everyone who scanned for one class
def class_rows(class_id):
    conn = get_db()
    rows = conn.execute("""
        SELECT u.name, u.id_number, u.role, a.status, a.scanned_at
        FROM attendance a JOIN users u ON u.id = a.user_id
        WHERE a.class_id = ? ORDER BY a.scanned_at
    """, (class_id,)).fetchall()
    conn.close()
    return rows

# 16. Report page for one class
@app.route("/class/<int:class_id>/report")
@login_required("Teacher")
def report(class_id):
    c = get_class(class_id)
    if c is None:
        abort(404)
    rows = class_rows(class_id)
    return render_template(
        "report.html", c=c, rows=rows,
        present=len([r for r in rows if r["status"] == "Present"]),
        late=len([r for r in rows if r["status"] == "Late"]))

# 17. Download the report as a CSV file (opens in Excel or Numbers)
@app.route("/class/<int:class_id>/export.csv")
@login_required("Teacher")
def export_csv(class_id):
    c = get_class(class_id)
    if c is None:
        abort(404)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name", "ID", "Role", "Status", "Scanned at"])
    for r in class_rows(class_id):
        writer.writerow([r["name"], r["id_number"], r["role"], r["status"], r["scanned_at"]])
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=pullup_class_{class_id}.csv"})

# 18. THE MAIN PART: a student scans the board QR and lands here
# NEW: if the class has the "in the class" check and the student is not on
# the class Wi-Fi, they are saved as Waiting for the teacher to approve
@app.route("/checkin/<int:class_id>/<token>")
@login_required()
def checkin(class_id, token):
    user = current_user()
    if user["role"] == "Teacher":
        return render_template("message.html", ok=False, title="Teachers can't check in",
                               text="Scan with a student account.")

    conn = get_db()
    c = conn.execute("SELECT * FROM classes WHERE id = ?", (class_id,)).fetchone()
    if c is None:
        conn.close()
        return render_template("message.html", ok=False, title="Class not found",
                               text="This QR code is not for an active class."), 404
    if not c["active"]:
        conn.close()
        return render_template("message.html", ok=False, title="Class has ended",
                               text="The teacher closed this class."), 400
    if not token_is_valid(class_id, token):
        conn.close()
        return render_template("message.html", ok=False, title="QR code expired",
                               text="Scan the code on the board again. It changes every 30 seconds."), 400

    # already scanned? show the earlier result instead of saving twice
    existing = conn.execute("SELECT * FROM attendance WHERE class_id = ? AND user_id = ?",
                            (class_id, user["id"])).fetchone()
    if existing:
        conn.close()
        if existing["status"] == "Waiting":
            return render_template("message.html", ok=False, title="Waiting for approval",
                                   text="Your teacher can see your name on the board. Let them know you are here.",
                                   status="Waiting")
        return render_template("message.html", ok=True, title="Already checked in",
                               text=f"{c['title']}: you were marked at {existing['scanned_at'][11:16]}.",
                               status=existing["status"])

    now = local_now()

    # NEW: the "in the class" check itself
    if c["in_class_only"] and not same_wifi(c):
        conn.execute("INSERT INTO attendance (class_id, user_id, scanned_at, status) VALUES (?, ?, ?, ?)",
                     (class_id, user["id"], now.strftime(TIME_FORMAT), "Waiting"))
        conn.commit()
        conn.close()
        return render_template("message.html", ok=False, title="Waiting for approval",
                               text="You are not on the class Wi-Fi, so your teacher needs to approve you. Your name is on the board now — let the teacher know.",
                               status="Waiting")

    # Present before the late cutoff, Late after it
    start = datetime.strptime(c["start_time"], TIME_FORMAT)
    minutes_after_start = (now - start).total_seconds() / 60
    status = "Late" if minutes_after_start > c["late_minutes"] else "Present"

    conn.execute("INSERT INTO attendance (class_id, user_id, scanned_at, status) VALUES (?, ?, ?, ?)",
                 (class_id, user["id"], now.strftime(TIME_FORMAT), status))
    conn.commit()
    conn.close()
    return render_template("message.html", ok=True, title=f"You're in, {user['name'].split()[0]}",
                           text=f"{c['title']} at {now.strftime('%H:%M')}", status=status)

# 19. Student page: their own attendance history
@app.route("/student")
@login_required()
def student():
    conn = get_db()
    history = conn.execute("""
        SELECT c.title, t.name AS teacher, a.scanned_at, a.status
        FROM attendance a
        JOIN classes c ON c.id = a.class_id
        JOIN users t ON t.id = c.teacher_id
        WHERE a.user_id = ? ORDER BY a.id DESC
    """, (current_user()["id"],)).fetchall()
    conn.close()
    return render_template("student.html", history=history)

# 20. Start the server. host="0.0.0.0" lets phones on the same Wi-Fi reach it.
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=True)
