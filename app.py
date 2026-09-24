from flask import Flask, request, render_template, redirect as flask_redirect, g, send_from_directory
import sqlite3
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "database", "university.db")
import hmac
import hashlib
import urllib.parse
import base64
from datetime import datetime
from werkzeug.utils import secure_filename


app = Flask(__name__)
AUTH_SECRET = "student_management_system_final_exam_2026"


# ONE-REQUEST MESSAGE SYSTEM
def flash(message, category="message"):
    """Store a one-request message without persistent browser state."""
    if not hasattr(g, "_messages"):
        g._messages = []
    g._messages.append(str(message))


def get_flashed_messages(with_categories=False, category_filter=None):
    """Retrieve messages without using Flask's persistent state mechanism."""
    messages = list(getattr(g, "_messages", []))
    messages.extend(request.args.getlist("message"))
    if category_filter:
        return []
    if with_categories:
        return [("message", message) for message in messages]
    return messages


app.jinja_env.globals["get_flashed_messages"] = get_flashed_messages

ALLOWED_ASSIGNMENT_EXTENSIONS = {"pdf"}
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads", "assignments")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
os.makedirs(UPLOAD_FOLDER, exist_ok=True)




# =========================================================
# SHARED HELPERS
# =========================================================
def make_auth_token(role, user_id):
    """Create a signed login token for the current request."""
    value = f"{role}:{user_id}".encode()
    return hmac.new(AUTH_SECRET.encode(), value, hashlib.sha256).hexdigest()


def auth_params(role, user_id):
    return {
        "role": role,
        "id": user_id,
        "token": make_auth_token(role, user_id),
    }


app.jinja_env.globals["make_auth_token"] = make_auth_token


def make_hod_leave_action_token(hod_id):
    """Create a self-contained signed token for HOD leave-history actions."""
    payload = f"hod:{hod_id}".encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    signature = hmac.new(AUTH_SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def read_hod_leave_action_token(token):
    """Return the HOD ID encoded in a valid leave-action token."""
    try:
        encoded, signature = token.rsplit(".", 1)
        padding = "=" * (-len(encoded) % 4)
        payload = base64.urlsafe_b64decode(encoded + padding)
        expected = hmac.new(AUTH_SECRET.encode(), payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        text = payload.decode()
        prefix, hod_id = text.split(":", 1)
        if prefix != "hod" or not hod_id:
            return None
        return hod_id
    except Exception:
        return None


app.jinja_env.globals["make_hod_leave_action_token"] = make_hod_leave_action_token


def current_user():
    """Read the logged-in identity from the signed URL parameters."""
    # Authentication can arrive through the query string or a POST form.
    # Reading request.values keeps destructive POST actions (such as HOD
    # leave-history deletion) tab-safe even if a form action loses its query
    # parameters during browser-side navigation.
    role = request.values.get("role", "")
    user_id = request.values.get("id", "")
    token = request.values.get("token", "")
    if role not in {"admin", "hod", "teacher", "student"} or not user_id or not token:
        return None, None
    if not hmac.compare_digest(token, make_auth_token(role, user_id)):
        return None, None
    return role, user_id


def get_hod_teacher_id(hod_id):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute("SELECT teacher_id FROM hods WHERE hod_id = ?", (hod_id,))
    row = cursor.fetchone()
    connection.close()
    return row[0] if row else None


def _attach_messages(location):
    messages = list(getattr(g, "_messages", []))
    if not messages:
        return location
    separator = "&" if "?" in location else "?"
    encoded = urllib.parse.urlencode([("message", message) for message in messages])
    g._messages = []
    return location + separator + encoded


def auth_redirect(path, role, user_id, code=302):
    separator = "&" if "?" in path else "?"
    location = path + separator + urllib.parse.urlencode(auth_params(role, user_id))
    return flask_redirect(_attach_messages(location), code=code)


def redirect(location, code=302):
    role, user_id = current_user()
    if role and user_id and location.startswith("/") and location not in {"/", "/logout", "/student_login", "/teacher_login", "/hod_login", "/admin_login"}:
        separator = "&" if "?" in location else "?"
        location = location + separator + urllib.parse.urlencode(auth_params(role, user_id))
    return flask_redirect(_attach_messages(location), code=code)


def create_notification(connection, sender_role, sender_id, title, message, target_scope, department=None, semester=None, recipient_ids=None):
    """Create one notification and independent recipient records."""
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO notifications
        (sender_role, sender_id, title, message, target_scope, department, semester)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (sender_role, sender_id, title, message, target_scope, department, semester))
    notification_id = cursor.lastrowid

    for role, user_id in (recipient_ids or []):
        cursor.execute("""
            INSERT OR IGNORE INTO notification_recipients
            (notification_id, recipient_role, recipient_user_id)
            VALUES (?, ?, ?)
        """, (notification_id, role, user_id))

    return notification_id


def get_notification_recipients(cursor, sender_role, department=None, semester=None, teacher_id=None):
    recipients = []
    if sender_role == "admin":
        for row in cursor.execute("SELECT student_id FROM students").fetchall():
            recipients.append(("student", row[0]))
        for row in cursor.execute("SELECT teacher_id FROM teachers").fetchall():
            recipients.append(("teacher", row[0]))
        for row in cursor.execute("SELECT hod_id FROM hods").fetchall():
            recipients.append(("hod", row[0]))
    elif sender_role == "hod":
        for row in cursor.execute("SELECT student_id FROM students WHERE department = ?", (department,)).fetchall():
            recipients.append(("student", row[0]))
        for row in cursor.execute("SELECT teacher_id FROM teachers WHERE department = ?", (department,)).fetchall():
            recipients.append(("teacher", row[0]))
    elif sender_role == "teacher":
        query = """
            SELECT DISTINCT students.student_id
            FROM students
            JOIN student_subjects ON student_subjects.student_id = students.student_id
            JOIN subjects ON subjects.subject_id = student_subjects.subject_id
            JOIN teacher_subjects ON teacher_subjects.subject_id = subjects.subject_id
            WHERE teacher_subjects.teacher_id = ?
            AND students.department = ?
            AND students.semester = ?
        """
        for row in cursor.execute(query, (teacher_id, department, semester)).fetchall():
            recipients.append(("student", row[0]))
    return recipients


def notification_role_home(role):
    return {
        "student": "/dashboard",
        "teacher": "/teacher_dashboard",
        "hod": "/hod_dashboard",
        "admin": "/admin_dashboard"
    }.get(role, "/")


# =========================================================
# GLOBAL ROUTES
# =========================================================

@app.route("/")
def home():
    return render_template("INDEX.HTML")


@app.route("/logout")
def logout():
    role, _ = current_user()
    return flask_redirect({
        "student": "/student_login",
        "teacher": "/teacher_login",
        "hod": "/hod_login",
        "admin": "/admin_login",
    }.get(role, "/"))


# =========================================================
# STUDENT ROUTES
# =========================================================

@app.route("/student_login")
def login_page():
    return render_template("student_login.HTML")


@app.route("/student_login", methods=["POST"])
def student_login_post():
    student_id = request.form["student_id"]
    password = request.form["password"]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
    SELECT *FROM students
    WHERE student_id = ?
    AND password = ?
    """,(student_id,password))

    student = cursor.fetchone()

    if student:
        connection.close()
        return auth_redirect("/student_dashboard", "student", student["student_id"])

    else:
        connection.close()
        flash("Invalid Student ID or Password")
        return redirect("/student_login")


@app.route("/dashboard")
def std_dashboard():

    if current_user()[0] != "student":
        return redirect("/student_login")

    student_id = current_user()[1]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
    SELECT *
    FROM students
    WHERE student_id = ?
    """, (student_id,))

    student = cursor.fetchone()

    connection.close()

    return render_template(
        "student_dashboard.html",
        student=student
    )


@app.route("/student_dashboard")
def student_dashboard():

    if current_user()[0] != "student":
        return redirect("/student_login")

    student_id = current_user()[1]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
    SELECT *
    FROM students
    WHERE student_id = ?
    """, (student_id,))

    student = cursor.fetchone()

    connection.close()

    return render_template(
        "student_dashboard.html",
        student=student
    )


@app.route("/profile")
def profile():

    if current_user()[0] != "student":
        return redirect("/student_login")

    student_id = current_user()[1]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
    SELECT *
    FROM students
    WHERE student_id=?
    """,(student_id,))

    student = cursor.fetchone()

    connection.close()

    return render_template(
        "profile.html",
        student=student
    )


@app.route("/marks")
def marks():

    if current_user()[0] != "student":
        return redirect("/student_login")

    student_id = current_user()[1]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        marks.mark_id,
        marks.student_id,
        marks.subject_id,
        subjects.subject_name,
        marks.internal_marks,
        marks.external_marks,
        marks.total_marks

    FROM marks

    JOIN subjects
    ON marks.subject_id = subjects.subject_id

    WHERE marks.student_id = ?

    ORDER BY subjects.subject_name
    """, (student_id,))

    marks = cursor.fetchall()

    connection.close()

    return render_template(
        "marks.html",
        marks=marks
    )


@app.route("/attendance")
def attendance():

    if current_user()[0] != "student":
        return redirect("/student_login")

    student_id = current_user()[1]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        attendance.attendance_id,
        attendance.student_id,
        attendance.subject_id,
        subjects.subject_name,
        attendance.total_classes,
        attendance.present_classes

    FROM attendance

    JOIN subjects
        ON attendance.subject_id = subjects.subject_id

    WHERE attendance.student_id = ?

    ORDER BY subjects.subject_name
    """, (student_id,))

    attendance = cursor.fetchall()

    connection.close()

    return render_template(
        "attendance.html",
        attendance=attendance
    )


@app.route("/leave_request")
def leave_request():

    if current_user()[0] != "student":
        return redirect("/student_login")

    student_id = current_user()[1]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM students
        WHERE student_id = ?
    """, (student_id,))
    student = cursor.fetchone()

    cursor.execute("""
        SELECT hod_id, name, department
        FROM hods
        WHERE department = ?
    """, (student["department"],))
    hod = cursor.fetchone()

    connection.close()

    return render_template(
        "leave_request.html",
        student=student,
        hod=hod
    )


@app.route("/apply_leave", methods=["POST"])
def apply_leave():

    if current_user()[0] != "student":
        return redirect("/student_login")

    student_id = current_user()[1]
    from_date = request.form.get("from_date", "").strip()
    to_date = request.form.get("to_date", "").strip()
    reason = request.form.get("reason", "").strip()

    if not from_date or not to_date or not reason:
        flash("All leave fields are required")
        return redirect("/leave_request")

    try:
        start = datetime.strptime(from_date, "%Y-%m-%d").date()
        end = datetime.strptime(to_date, "%Y-%m-%d").date()
    except ValueError:
        flash("Please enter valid dates")
        return redirect("/leave_request")

    if end < start:
        flash("To date cannot be before from date")
        return redirect("/leave_request")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("SELECT department FROM students WHERE student_id = ?", (student_id,))
    student = cursor.fetchone()

    if not student:
        connection.close()
        return redirect("/student_login")

    cursor.execute("""
        SELECT hod_id
        FROM hods
        WHERE department = ?
    """, (student["department"],))
    hod = cursor.fetchone()

    if not hod:
        connection.close()
        flash("No HOD is assigned to your department. Please contact the administrator.")
        return redirect("/leave_request")

    # Do not allow another pending request with an overlapping date range.
    cursor.execute("""
        SELECT leave_id
        FROM leave_requests
        WHERE student_id = ?
        AND status = 'Pending'
        AND from_date <= ?
        AND to_date >= ?
    """, (student_id, to_date, from_date))

    existing = cursor.fetchone()

    if existing:
        connection.close()
        flash("You already have a pending leave request for these dates")
        return redirect("/leave_request")

    cursor.execute("""
        INSERT INTO leave_requests
        (student_id, hod_id, from_date, to_date, reason, status)
        VALUES (?, ?, ?, ?, ?, 'Pending')
    """, (
        student_id,
        hod["hod_id"],
        from_date,
        to_date,
        reason
    ))

    create_notification(
        connection, "student", student_id,
        "New Student Leave Request",
        f"A student leave request from {student_id} is waiting for your review.",
        "leave", student["department"], None, [("hod", hod["hod_id"])]
    )

    connection.commit()
    connection.close()

    flash("Leave request submitted successfully")
    return redirect("/my_leave_requests")


@app.route("/my_leave_requests")
def my_leave_requests():

    if current_user()[0] != "student":
        return redirect("/student_login")

    student_id = current_user()[1]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            leave_requests.*,
            hods.name AS hod_name
        FROM leave_requests
        LEFT JOIN hods
            ON leave_requests.hod_id = hods.hod_id
        WHERE leave_requests.student_id = ?
        AND leave_requests.student_deleted = 0
        ORDER BY leave_requests.leave_id DESC
    """, (student_id,))

    leave_requests = cursor.fetchall()
    cursor.execute("SELECT leaves_taken FROM students WHERE student_id = ?", (student_id,))
    student_row = cursor.fetchone()
    leaves_taken = student_row["leaves_taken"] if student_row else 0
    connection.close()

    return render_template(
        "my_leave_requests.html",
        leave_requests=leave_requests,
        leaves_taken=leaves_taken
    )


@app.route("/delete_leave_request", methods=["POST"])
def delete_leave_request():
    if current_user()[0] != "student":
        return redirect("/student_login")

    leave_id = request.form.get("leave_id")
    if not leave_id:
        return redirect("/my_leave_requests")

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute("""
        UPDATE leave_requests
        SET student_deleted = 1
        WHERE leave_id = ?
        AND student_id = ?
        AND status IN ('Approved', 'Rejected')
        AND student_deleted = 0
    """, (leave_id, current_user()[1]))

    if cursor.rowcount == 0:
        connection.close()
        flash("Only decided leave requests can be deleted")
        return redirect("/my_leave_requests")

    connection.commit()
    connection.close()
    flash("Leave request deleted from your history")
    return redirect("/my_leave_requests")


# =========================================================
# TEACHER ROUTES
# =========================================================

@app.route("/teacher_login")
def teacher_login():
    return render_template("teacher_login.html")


@app.route("/teacher_login", methods=["POST"])
def teacher_login_post():
    teacher_id = request.form["teacher_id"]
    password = request.form["password"]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
    SELECT *FROM teachers
    WHERE teacher_id = ?
    AND password = ?
    """,(teacher_id,password))

    teacher = cursor.fetchone()

    if teacher:
        connection.close()
        return auth_redirect("/teacher_dashboard", "teacher", teacher["teacher_id"])

    else:
        connection.close()
        flash("Invalid Teacher ID or Password")
        return redirect("/teacher_login")


@app.route("/teacher_marks/<student_id>")
def teacher_marks(student_id):

    if current_user()[0] != "teacher":
        return redirect("/teacher_login")

    teacher_id = current_user()[1]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        marks.mark_id,
        marks.student_id,
        marks.subject_id,
        subjects.subject_name,
        subjects.subject_type,
        marks.internal_marks,
        marks.external_marks,
        marks.total_marks

    FROM marks

    JOIN subjects
        ON marks.subject_id = subjects.subject_id

    JOIN teacher_subjects
        ON marks.subject_id = teacher_subjects.subject_id

    WHERE marks.student_id = ?
    AND teacher_subjects.teacher_id = ?

    ORDER BY subjects.subject_name
    """, (
        student_id,
        teacher_id
    ))

    marks = cursor.fetchall()

    connection.close()

    return render_template(
        "teacher_marks.html",
        marks=marks,
        student_id=student_id
    )


@app.route("/save_marks", methods=["POST"])
def save_marks():

    if current_user()[0] != "teacher":
        return redirect("/teacher_login")

    teacher_id = current_user()[1]

    mark_ids = request.form.getlist("mark_id")
    internal_marks = request.form.getlist("internal_marks")
    external_marks = request.form.getlist("external_marks")

    student_id = request.form["student_id"]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    for i in range(len(mark_ids)):

        mark_id = mark_ids[i]

        # -------------------------------------------------
        # Check that this mark belongs to this student
        # and that its subject is assigned to this teacher
        # -------------------------------------------------

        cursor.execute("""
        SELECT
            marks.mark_id,
            marks.student_id,
            marks.subject_id,
            subjects.subject_type

        FROM marks

        JOIN teacher_subjects
            ON marks.subject_id = teacher_subjects.subject_id

        JOIN subjects
            ON marks.subject_id = subjects.subject_id

        WHERE marks.mark_id = ?
        AND marks.student_id = ?
        AND teacher_subjects.teacher_id = ?
        """, (
            mark_id,
            student_id,
            teacher_id
        ))

        mark = cursor.fetchone()

        # -------------------------------------------------
        # Unauthorized
        # -------------------------------------------------

        if not mark:

            connection.close()

            flash(
                "You are not authorized to modify this subject"
            )

            return redirect(
                f"/teacher_marks/{student_id}"
            )

        # -------------------------------------------------
        # Convert submitted marks to integers
        # -------------------------------------------------

        try:

            internal = int(internal_marks[i])
            external = int(external_marks[i])

        except (ValueError, TypeError):

            connection.close()

            flash("Marks must be valid numbers")

            return redirect(
                f"/teacher_marks/{student_id}"
            )

        # -------------------------------------------------
        # THEORY
        # Internal = 20
        # External = 80
        # Total = 100
        # -------------------------------------------------

        if mark["subject_type"] == "Theory":

            if internal < 0 or internal > 20:

                connection.close()

                flash(
                    "Theory internal marks must be between 0 and 20"
                )

                return redirect(
                    f"/teacher_marks/{student_id}"
                )

            if external < 0 or external > 80:

                connection.close()

                flash(
                    "Theory external marks must be between 0 and 80"
                )

                return redirect(
                    f"/teacher_marks/{student_id}"
                )

        # -------------------------------------------------
        # PRACTICAL
        # Internal = 10
        # External = 40
        # Total = 50
        # -------------------------------------------------

        elif mark["subject_type"] == "Practical":

            if internal < 0 or internal > 10:

                connection.close()

                flash(
                    "Practical internal marks must be between 0 and 10"
                )

                return redirect(
                    f"/teacher_marks/{student_id}"
                )

            if external < 0 or external > 40:

                connection.close()

                flash(
                    "Practical external marks must be between 0 and 40"
                )

                return redirect(
                    f"/teacher_marks/{student_id}"
                )

        # -------------------------------------------------
        # Calculate total on SERVER
        # -------------------------------------------------

        total = internal + external

        # -------------------------------------------------
        # Update marks
        # -------------------------------------------------

        cursor.execute("""
        UPDATE marks

        SET internal_marks = ?,
            external_marks = ?,
            total_marks = ?

        WHERE mark_id = ?
        AND student_id = ?
        """, (
            internal,
            external,
            total,
            mark_id,
            student_id
        ))

    connection.commit()
    connection.close()

    flash("Marks updated successfully")

    return redirect(
        f"/teacher_marks/{student_id}"
    )


@app.route("/search_student", methods=["POST"])
def search_student():

    if current_user()[0] != "teacher":
        return redirect("/teacher_login")

    student_id = request.form["student_id"]
    teacher_id = current_user()[1]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("SELECT department FROM teachers WHERE teacher_id = ?", (teacher_id,))
    teacher = cursor.fetchone()

    if not teacher:
        connection.close()
        return redirect("/teacher_login")

    cursor.execute("""
        SELECT *
        FROM students
        WHERE student_id = ?
    """, (student_id,))

    student = cursor.fetchone()

    if student and student["department"] != teacher["department"]:
        connection.close()
        flash("You can't access another department student's details.")
        return redirect("/teacher_dashboard")

    connection.close()

    if student:
        return render_template("student_details.html", student=student)

    flash("Student Not Found")
    return redirect("/teacher_dashboard")


@app.route("/teacher_attendance/<student_id>")
def teacher_attendance(student_id):

    if current_user()[0] != "teacher":
        return redirect("/teacher_login")

    teacher_id = current_user()[1]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        attendance.attendance_id,
        attendance.student_id,
        attendance.subject_id,
        subjects.subject_name,
        subjects.subject_type,
        attendance.total_classes,
        attendance.present_classes

    FROM attendance

    JOIN subjects
        ON attendance.subject_id = subjects.subject_id

    JOIN teacher_subjects
        ON attendance.subject_id = teacher_subjects.subject_id

    WHERE attendance.student_id = ?
    AND teacher_subjects.teacher_id = ?

    ORDER BY subjects.subject_name
    """, (
        student_id,
        teacher_id
    ))

    attendance = cursor.fetchall()

    connection.close()

    return render_template(
        "teacher_attendance.html",
        attendance=attendance,
        student_id=student_id
    )


@app.route("/save_attendance", methods=["POST"])
def save_attendance():

    if current_user()[0] != "teacher":
        return redirect("/teacher_login")

    teacher_id = current_user()[1]

    attendance_ids = request.form.getlist("attendance_id")
    total_classes = request.form.getlist("total_classes")
    present_classes = request.form.getlist("present_classes")

    student_id = request.form["student_id"]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    for i in range(len(attendance_ids)):

        attendance_id = attendance_ids[i]

        # -------------------------------------------------
        # Check that this attendance belongs to this
        # student AND the subject is currently assigned
        # to the logged-in teacher
        # -------------------------------------------------

        cursor.execute("""
        SELECT
            attendance.attendance_id,
            attendance.student_id,
            attendance.subject_id

        FROM attendance

        JOIN teacher_subjects
            ON attendance.subject_id = teacher_subjects.subject_id

        WHERE attendance.attendance_id = ?
        AND attendance.student_id = ?
        AND teacher_subjects.teacher_id = ?
        """, (
            attendance_id,
            student_id,
            teacher_id
        ))

        attendance = cursor.fetchone()

        # -------------------------------------------------
        # Unauthorized
        # -------------------------------------------------

        if not attendance:

            connection.close()

            flash(
                "You are not authorized to modify this subject"
            )

            return redirect(
                f"/teacher_attendance/{student_id}"
            )

        # -------------------------------------------------
        # Convert values to integers
        # -------------------------------------------------

        try:

            total = int(total_classes[i])
            present = int(present_classes[i])

        except (ValueError, TypeError):

            connection.close()

            flash(
                "Attendance values must be valid numbers"
            )

            return redirect(
                f"/teacher_attendance/{student_id}"
            )

        # -------------------------------------------------
        # Validate total classes
        # -------------------------------------------------

        if total < 0:

            connection.close()

            flash(
                "Total classes cannot be negative"
            )

            return redirect(
                f"/teacher_attendance/{student_id}"
            )

        # -------------------------------------------------
        # Validate present classes
        # -------------------------------------------------

        if present < 0:

            connection.close()

            flash(
                "Present classes cannot be negative"
            )

            return redirect(
                f"/teacher_attendance/{student_id}"
            )

        # -------------------------------------------------
        # Present cannot exceed total
        # -------------------------------------------------

        if present > total:

            connection.close()

            flash(
                "Present classes cannot be greater than total classes"
            )

            return redirect(
                f"/teacher_attendance/{student_id}"
            )

        # -------------------------------------------------
        # Update attendance
        # -------------------------------------------------

        cursor.execute("""
        UPDATE attendance

        SET total_classes = ?,
            present_classes = ?

        WHERE attendance_id = ?
        AND student_id = ?
        """, (
            total,
            present,
            attendance_id,
            student_id
        ))

    connection.commit()
    connection.close()

    flash("Attendance updated successfully")

    return redirect(
        f"/teacher_attendance/{student_id}"
    )


@app.route("/teacher_dashboard")
def teacher_dashboard():

    if current_user()[0] != "teacher":
        return redirect("/teacher_login")

    teacher_id = current_user()[1]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""

    SELECT *

    FROM teachers

    WHERE teacher_id=?

    """,(teacher_id,))

    teacher = cursor.fetchone()

    connection.close()

    return render_template(
        "teacher_dashboard.html",
        teacher=teacher
    )


@app.route("/teacher_leave_request")
def teacher_leave_request():

    if current_user()[0] != "teacher":
        return redirect("/teacher_login")

    teacher_id = current_user()[1]
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM teachers WHERE teacher_id = ?", (teacher_id,))
    teacher = cursor.fetchone()

    if not teacher:
        connection.close()
        return redirect("/teacher_login")

    # A HOD is also a teacher, but their own leave cannot be approved by themselves.
    cursor.execute("SELECT hod_id FROM hods WHERE teacher_id = ?", (teacher_id,))
    is_hod = cursor.fetchone() is not None

    connection.close()

    return render_template(
        "teacher_leave_request.html",
        teacher=teacher,
        is_hod=is_hod
    )


@app.route("/apply_teacher_leave", methods=["POST"])
def apply_teacher_leave():

    if current_user()[0] != "teacher":
        return redirect("/teacher_login")

    teacher_id = current_user()[1]
    from_date = request.form.get("from_date", "").strip()
    to_date = request.form.get("to_date", "").strip()
    reason = request.form.get("reason", "").strip()

    if not from_date or not to_date or not reason:
        flash("All leave fields are required")
        return redirect("/teacher_leave_request")

    try:
        start_date = datetime.strptime(from_date, "%Y-%m-%d").date()
        end_date = datetime.strptime(to_date, "%Y-%m-%d").date()
    except ValueError:
        flash("Please enter valid dates")
        return redirect("/teacher_leave_request")

    if end_date < start_date:
        flash("To date cannot be before from date")
        return redirect("/teacher_leave_request")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("SELECT department FROM teachers WHERE teacher_id = ?", (teacher_id,))
    teacher = cursor.fetchone()

    if not teacher:
        connection.close()
        return redirect("/teacher_login")

    # HODs are teachers too, but an HOD cannot send a leave request to themselves.
    cursor.execute("SELECT hod_id FROM hods WHERE teacher_id = ?", (teacher_id,))
    if cursor.fetchone():
        connection.close()
        flash("As HOD, your leave must be handled by the administrator because the department HOD cannot approve their own leave.")
        return redirect("/teacher_leave_request")

    cursor.execute("SELECT hod_id FROM hods WHERE department = ?", (teacher["department"],))
    hod = cursor.fetchone()

    if not hod:
        connection.close()
        flash("No HOD is assigned to your department. Please contact the administrator.")
        return redirect("/teacher_leave_request")

    cursor.execute("""
        SELECT teacher_leave_id
        FROM teacher_leave_requests
        WHERE teacher_id = ?
        AND status = 'Pending'
        AND from_date <= ?
        AND to_date >= ?
    """, (teacher_id, to_date, from_date))

    if cursor.fetchone():
        connection.close()
        flash("You already have a pending leave request for these dates")
        return redirect("/my_teacher_leave_requests")

    cursor.execute("""
        INSERT INTO teacher_leave_requests
        (teacher_id, hod_id, from_date, to_date, reason, status)
        VALUES (?, ?, ?, ?, ?, 'Pending')
    """, (teacher_id, hod["hod_id"], from_date, to_date, reason))

    create_notification(
        connection, "teacher", teacher_id,
        "New Teacher Leave Request",
        f"Teacher {teacher_id} has submitted a leave request for your review.",
        "leave", teacher["department"], None, [("hod", hod["hod_id"])]
    )

    connection.commit()
    connection.close()

    flash("Leave request submitted successfully")
    return redirect("/my_teacher_leave_requests")


@app.route("/my_teacher_leave_requests")
def my_teacher_leave_requests():

    if current_user()[0] != "teacher":
        return redirect("/teacher_login")

    teacher_id = current_user()[1]
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
        SELECT teacher_leave_requests.*, hods.name AS hod_name
        FROM teacher_leave_requests
        LEFT JOIN hods ON teacher_leave_requests.hod_id = hods.hod_id
        WHERE teacher_leave_requests.teacher_id = ?
        AND teacher_leave_requests.teacher_deleted = 0
        ORDER BY teacher_leave_requests.teacher_leave_id DESC
    """, (teacher_id,))

    leave_requests = cursor.fetchall()
    cursor.execute("SELECT * FROM teachers WHERE teacher_id = ?", (teacher_id,))
    teacher = cursor.fetchone()
    leaves_taken = teacher["leaves_taken"] if teacher and "leaves_taken" in teacher.keys() else 0
    connection.close()

    return render_template(
        "my_teacher_leave_requests.html",
        teacher=teacher,
        leave_requests=leave_requests,
        leaves_taken=leaves_taken
    )


@app.route("/teacher_leave_requests")
def teacher_leave_requests():
    return redirect("/my_teacher_leave_requests")


@app.route("/delete_teacher_leave_request", methods=["POST"])
def delete_teacher_leave_request():
    if current_user()[0] != "teacher":
        return redirect("/teacher_login")

    leave_id = request.form.get("teacher_leave_id")
    if not leave_id:
        return redirect("/my_teacher_leave_requests")

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute("""
        UPDATE teacher_leave_requests
        SET teacher_deleted = 1
        WHERE teacher_leave_id = ?
        AND teacher_id = ?
        AND status IN ('Approved', 'Rejected')
        AND teacher_deleted = 0
    """, (leave_id, current_user()[1]))

    if cursor.rowcount == 0:
        connection.close()
        flash("Only decided leave requests can be deleted")
        return redirect("/my_teacher_leave_requests")

    connection.commit()
    connection.close()
    flash("Leave request deleted from your history")
    return redirect("/my_teacher_leave_requests")


# =========================================================
# HOD ROUTES
# =========================================================

@app.route("/hod_login")
def hod_login():
    return render_template("hod_login.html")


@app.route("/hod_login", methods=["POST"])
def hod_login_post():

    hod_id = request.form["hod_id"]
    password = request.form["password"]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
        SELECT hods.*, teachers.name AS teacher_name, teachers.department AS teacher_department
        FROM hods
        LEFT JOIN teachers ON hods.teacher_id = teachers.teacher_id
        WHERE hods.hod_id = ?
        AND hods.password = ?
    """, (hod_id, password))

    hod = cursor.fetchone()
    connection.close()

    if hod:
        return auth_redirect("/hod_dashboard", "hod", hod["hod_id"])

    flash("Invalid HOD ID or Password")
    return redirect("/hod_login")


@app.route("/hod_dashboard")
def hod_dashboard():

    if current_user()[0] != "hod":
        return redirect("/hod_login")

    hod_id = current_user()[1]
    student_semester = request.args.get("student_semester", "")
    subject_semester = request.args.get("subject_semester", "")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
        SELECT hods.*, teachers.name AS teacher_name, teachers.department AS teacher_department,
               teachers.email AS teacher_email, teachers.phone AS teacher_phone
        FROM hods
        LEFT JOIN teachers ON hods.teacher_id = teachers.teacher_id
        WHERE hods.hod_id = ?
    """, (hod_id,))
    hod = cursor.fetchone()

    if not hod:
        connection.close()
        return redirect("/hod_login")

    department = hod["teacher_department"] or hod["department"]

    cursor.execute("SELECT COUNT(*) AS count FROM students WHERE department = ?", (department,))
    total_student_count = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM teachers WHERE department = ?", (department,))
    teacher_count = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM subjects WHERE department = ?", (department,))
    total_subject_count = cursor.fetchone()["count"]

    cursor.execute("""
        SELECT COUNT(*) AS count FROM leave_requests
        JOIN students ON leave_requests.student_id = students.student_id
        WHERE students.department = ? AND leave_requests.status = 'Pending' AND leave_requests.hod_deleted = 0
    """, (department,))
    student_pending = cursor.fetchone()["count"]

    cursor.execute("""
        SELECT COUNT(*) AS count FROM teacher_leave_requests
        JOIN teachers ON teacher_leave_requests.teacher_id = teachers.teacher_id
        WHERE teachers.department = ? AND teacher_leave_requests.status = 'Pending' AND teacher_leave_requests.hod_deleted = 0
    """, (department,))
    teacher_pending = cursor.fetchone()["count"]
    pending_leave_count = student_pending + teacher_pending

    cursor.execute("""
        SELECT teacher_id, name, email, phone
        FROM teachers WHERE department = ? ORDER BY name
    """, (department,))
    teachers = cursor.fetchall()

    cursor.execute("""
        SELECT leave_requests.leave_id, leave_requests.from_date, leave_requests.to_date,
               leave_requests.reason, leave_requests.status, leave_requests.applied_at,
               students.student_id, students.name AS student_name, students.semester
        FROM leave_requests
        JOIN students ON leave_requests.student_id = students.student_id
        WHERE students.department = ?
          AND leave_requests.hod_deleted = 0
        ORDER BY CASE WHEN leave_requests.status = 'Pending' THEN 0 ELSE 1 END,
                 leave_requests.leave_id DESC
    """, (department,))
    student_leave_requests = cursor.fetchall()

    cursor.execute("""
        SELECT teacher_leave_requests.teacher_leave_id, teacher_leave_requests.from_date,
               teacher_leave_requests.to_date, teacher_leave_requests.reason,
               teacher_leave_requests.status, teacher_leave_requests.applied_at,
               teachers.teacher_id, teachers.name AS teacher_name
        FROM teacher_leave_requests
        JOIN teachers ON teacher_leave_requests.teacher_id = teachers.teacher_id
        WHERE teachers.department = ?
          AND teacher_leave_requests.hod_deleted = 0
        ORDER BY CASE WHEN teacher_leave_requests.status = 'Pending' THEN 0 ELSE 1 END,
                 teacher_leave_requests.teacher_leave_id DESC
    """, (department,))
    teacher_leave_requests = cursor.fetchall()

    connection.close()

    return render_template(
        "hod_dashboard.html",
        hod=hod,
        department=department,
        total_student_count=total_student_count,
        teacher_count=teacher_count,
        total_subject_count=total_subject_count,
        pending_leave_count=pending_leave_count,
        teachers=teachers,
        students=[],
        subjects=[],
        student_leave_requests=student_leave_requests,
        teacher_leave_requests=teacher_leave_requests,
        student_semester=student_semester,
        subject_semester=subject_semester,
        auth_query=urllib.parse.urlencode(auth_params("hod", hod_id))
    )


@app.route("/hod_dashboard_data")
def hod_dashboard_data():
    if current_user()[0] != "hod":
        return {"error": "Unauthorized"}, 401

    data_type = request.args.get("type", "")
    semester = request.args.get("semester", "").strip()

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
        SELECT hods.*, teachers.department AS teacher_department
        FROM hods
        LEFT JOIN teachers ON hods.teacher_id = teachers.teacher_id
        WHERE hods.hod_id = ?
    """, (current_user()[1],))
    hod = cursor.fetchone()
    if not hod:
        connection.close()
        return {"error": "Invalid HOD login"}, 401

    department = hod["teacher_department"] or hod["department"]

    if data_type == "students":
        if not semester:
            connection.close()
            return {"items": []}
        cursor.execute("""
            SELECT student_id, name, semester, email, phone
            FROM students
            WHERE department = ? AND semester = ?
            ORDER BY student_id
        """, (department, semester))
        items = [dict(row) for row in cursor.fetchall()]
    elif data_type == "subjects":
        if not semester:
            connection.close()
            return {"items": []}
        cursor.execute("""
            SELECT subject_id, subject_name, semester, subject_type
            FROM subjects
            WHERE department = ? AND semester = ?
            ORDER BY subject_name
        """, (department, semester))
        items = [dict(row) for row in cursor.fetchall()]
    else:
        connection.close()
        return {"error": "Invalid data type"}, 400

    connection.close()
    return {"items": items}


@app.route("/hod_leave/<int:leave_id>")
def hod_leave_detail(leave_id):

    if current_user()[0] != "hod":
        return redirect("/hod_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
        SELECT hods.*, teachers.department AS teacher_department
        FROM hods LEFT JOIN teachers ON hods.teacher_id = teachers.teacher_id
        WHERE hods.hod_id = ?
    """, (current_user()[1],))
    hod = cursor.fetchone()
    department = hod["teacher_department"] or hod["department"]

    cursor.execute("""
        SELECT leave_requests.*, students.student_id, students.name AS student_name,
               students.department, students.semester, students.email, students.phone
        FROM leave_requests
        JOIN students ON leave_requests.student_id = students.student_id
        WHERE leave_requests.leave_id = ?
        AND students.department = ?
        AND leave_requests.hod_id = ?
    """, (leave_id, department, hod["hod_id"]))
    leave_request = cursor.fetchone()
    connection.close()

    if not leave_request:
        flash("Leave request not found or not assigned to your department")
        return redirect("/hod_dashboard")

    return render_template("hod_leave_detail.html", hod=hod, leave_request=leave_request, request_type="student", auth_query=urllib.parse.urlencode(auth_params("hod", hod["hod_id"])))


@app.route("/hod_teacher_leave/<int:leave_id>")
def hod_teacher_leave_detail(leave_id):

    if current_user()[0] != "hod":
        return redirect("/hod_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
        SELECT hods.*, teachers.department AS teacher_department
        FROM hods LEFT JOIN teachers ON hods.teacher_id = teachers.teacher_id
        WHERE hods.hod_id = ?
    """, (current_user()[1],))
    hod = cursor.fetchone()
    department = hod["teacher_department"] or hod["department"]

    cursor.execute("""
        SELECT teacher_leave_requests.*, teachers.teacher_id, teachers.name AS teacher_name,
               teachers.department, teachers.email, teachers.phone
        FROM teacher_leave_requests
        JOIN teachers ON teacher_leave_requests.teacher_id = teachers.teacher_id
        WHERE teacher_leave_requests.teacher_leave_id = ?
        AND teachers.department = ?
        AND teacher_leave_requests.hod_id = ?
    """, (leave_id, department, hod["hod_id"]))
    leave_request = cursor.fetchone()
    connection.close()

    if not leave_request:
        flash("Teacher leave request not found or not assigned to your department")
        return redirect("/hod_dashboard")

    return render_template("hod_teacher_leave_detail.html", hod=hod, leave_request=leave_request, auth_query=urllib.parse.urlencode(auth_params("hod", hod["hod_id"])))


@app.route("/hod_approve_leave", methods=["POST"])
def hod_approve_leave():

    if current_user()[0] != "hod":
        return redirect("/hod_login")

    request_type = request.form.get("request_type", "student")
    leave_id = request.form["leave_id"]
    remark = request.form.get("remark", "").strip()

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
        SELECT hods.*, teachers.department AS teacher_department
        FROM hods LEFT JOIN teachers ON hods.teacher_id = teachers.teacher_id
        WHERE hods.hod_id = ?
    """, (current_user()[1],))
    hod = cursor.fetchone()
    department = hod["teacher_department"] or hod["department"]

    if request_type == "teacher":
        cursor.execute("""
            SELECT teacher_leave_requests.teacher_leave_id
            FROM teacher_leave_requests
            JOIN teachers ON teacher_leave_requests.teacher_id = teachers.teacher_id
            WHERE teacher_leave_requests.teacher_leave_id = ?
            AND teacher_leave_requests.hod_id = ?
            AND teachers.department = ?
            AND teacher_leave_requests.status = 'Pending'
        """, (leave_id, hod["hod_id"], department))
        valid = cursor.fetchone()
        table = "teacher_leave_requests"
        id_column = "teacher_leave_id"
    else:
        cursor.execute("""
            SELECT leave_requests.leave_id
            FROM leave_requests JOIN students ON leave_requests.student_id = students.student_id
            WHERE leave_requests.leave_id = ?
            AND leave_requests.hod_id = ?
            AND students.department = ?
            AND leave_requests.status = 'Pending'
        """, (leave_id, hod["hod_id"], department))
        valid = cursor.fetchone()
        table = "leave_requests"
        id_column = "leave_id"

    if not valid:
        connection.close()
        flash("You are not authorized to approve this leave request")
        return redirect("/hod_dashboard")

    cursor.execute(f"""
        UPDATE {table}
        SET status = 'Approved', hod_remark = ?, decided_at = CURRENT_TIMESTAMP
        WHERE {id_column} = ? AND status = 'Pending'
    """, (remark, leave_id))

    if cursor.rowcount == 1:
        if request_type == "teacher":
            cursor.execute("""
                UPDATE teachers
                SET leaves_taken = COALESCE(leaves_taken, 0) + 1
                WHERE teacher_id = (
                    SELECT teacher_id FROM teacher_leave_requests WHERE teacher_leave_id = ?
                )
            """, (leave_id,))
        else:
            cursor.execute("""
                UPDATE students
                SET leaves_taken = COALESCE(leaves_taken, 0) + 1
                WHERE student_id = (
                    SELECT student_id FROM leave_requests WHERE leave_id = ?
                )
            """, (leave_id,))

    # Notify the requester about the decision.
    if cursor.rowcount >= 0:
        if request_type == "teacher":
            cursor.execute("""
                SELECT teacher_leave_requests.teacher_id, teachers.department
                FROM teacher_leave_requests JOIN teachers ON teachers.teacher_id = teacher_leave_requests.teacher_id
                WHERE teacher_leave_requests.teacher_leave_id = ?
            """, (leave_id,))
            target = cursor.fetchone()
            if target:
                create_notification(
                    connection, "hod", hod["hod_id"], "Teacher Leave Approved",
                    f"Your leave request has been approved. Remark: {remark or 'No remark'}",
                    "leave_decision", target["department"], None, [("teacher", target["teacher_id"])]
                )
        else:
            cursor.execute("""
                SELECT leave_requests.student_id, students.department
                FROM leave_requests JOIN students ON students.student_id = leave_requests.student_id
                WHERE leave_requests.leave_id = ?
            """, (leave_id,))
            target = cursor.fetchone()
            if target:
                create_notification(
                    connection, "hod", hod["hod_id"], "Student Leave Approved",
                    f"Your leave request has been approved. Remark: {remark or 'No remark'}",
                    "leave_decision", target["department"], None, [("student", target["student_id"])]
                )

    connection.commit()
    connection.close()
    flash("Leave granted successfully")
    return redirect("/hod_dashboard")


@app.route("/hod_reject_leave", methods=["POST"])
def hod_reject_leave():

    if current_user()[0] != "hod":
        return redirect("/hod_login")

    request_type = request.form.get("request_type", "student")
    leave_id = request.form["leave_id"]
    remark = request.form.get("remark", "").strip()

    if not remark:
        target = f"/hod_teacher_leave/{leave_id}" if request_type == "teacher" else f"/hod_leave/{leave_id}"
        flash("Please enter a reason before rejecting the leave")
        return redirect(target)

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
        SELECT hods.*, teachers.department AS teacher_department
        FROM hods LEFT JOIN teachers ON hods.teacher_id = teachers.teacher_id
        WHERE hods.hod_id = ?
    """, (current_user()[1],))
    hod = cursor.fetchone()
    department = hod["teacher_department"] or hod["department"]

    if request_type == "teacher":
        cursor.execute("""
            SELECT teacher_leave_requests.teacher_leave_id
            FROM teacher_leave_requests JOIN teachers ON teacher_leave_requests.teacher_id = teachers.teacher_id
            WHERE teacher_leave_requests.teacher_leave_id = ?
            AND teacher_leave_requests.hod_id = ?
            AND teachers.department = ?
            AND teacher_leave_requests.status = 'Pending'
        """, (leave_id, hod["hod_id"], department))
        valid = cursor.fetchone()
        table = "teacher_leave_requests"
        id_column = "teacher_leave_id"
    else:
        cursor.execute("""
            SELECT leave_requests.leave_id
            FROM leave_requests JOIN students ON leave_requests.student_id = students.student_id
            WHERE leave_requests.leave_id = ?
            AND leave_requests.hod_id = ?
            AND students.department = ?
            AND leave_requests.status = 'Pending'
        """, (leave_id, hod["hod_id"], department))
        valid = cursor.fetchone()
        table = "leave_requests"
        id_column = "leave_id"

    if not valid:
        connection.close()
        flash("You are not authorized to reject this leave request")
        return redirect("/hod_dashboard")

    cursor.execute(f"""
        UPDATE {table}
        SET status = 'Rejected', hod_remark = ?, decided_at = CURRENT_TIMESTAMP
        WHERE {id_column} = ? AND status = 'Pending'
    """, (remark, leave_id))

    if request_type == "teacher":
        cursor.execute("""
            SELECT teacher_leave_requests.teacher_id, teachers.department
            FROM teacher_leave_requests JOIN teachers ON teachers.teacher_id = teacher_leave_requests.teacher_id
            WHERE teacher_leave_requests.teacher_leave_id = ?
        """, (leave_id,))
        target = cursor.fetchone()
        if target:
            create_notification(
                connection, "hod", hod["hod_id"], "Teacher Leave Rejected",
                f"Your leave request has been rejected. Remark: {remark}",
                "leave_decision", target["department"], None, [("teacher", target["teacher_id"])]
            )
    else:
        cursor.execute("""
            SELECT leave_requests.student_id, students.department
            FROM leave_requests JOIN students ON students.student_id = leave_requests.student_id
            WHERE leave_requests.leave_id = ?
        """, (leave_id,))
        target = cursor.fetchone()
        if target:
            create_notification(
                connection, "hod", hod["hod_id"], "Student Leave Rejected",
                f"Your leave request has been rejected. Remark: {remark}",
                "leave_decision", target["department"], None, [("student", target["student_id"])]
            )

    connection.commit()
    connection.close()
    flash("Leave request rejected")
    return redirect("/hod_dashboard")


# =========================================================
# INDEPENDENT HOD LEAVE DELETION
# =========================================================

@app.route("/hod_delete_leave_request/<request_type>/<int:leave_id>", methods=["GET", "POST"])
@app.route("/hod_delete_leave_request/<request_type>/<int:leave_id>/<token>", methods=["GET", "POST"])
def hod_delete_leave_request(request_type, leave_id, token=None):
    if request_type not in {"student", "teacher"}:
        return flask_redirect("/hod_login")

    # 1. Resolve HOD ID from either the action token OR the current URL parameters
    hod_id = read_hod_leave_action_token(token) if token else None
    if not hod_id:
        role, current_id = current_user()
        if role == "hod" and current_id:
            hod_id = current_id

    if not hod_id:
        return flask_redirect("/hod_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
        SELECT hods.hod_id, hods.department,
               teachers.department AS teacher_department
        FROM hods
        LEFT JOIN teachers ON hods.teacher_id = teachers.teacher_id
        WHERE hods.hod_id = ?
    """, (hod_id,))
    hod = cursor.fetchone()

    if not hod:
        connection.close()
        return flask_redirect("/hod_login")

    department = hod["teacher_department"] or hod["department"]

    # 2. Accept both 'Approved', 'Rejected', and 'Leave Granted'
    allowed_statuses = "('Approved', 'Rejected', 'Leave Granted')"

    if request_type == "teacher":
        cursor.execute(f"""
            UPDATE teacher_leave_requests
            SET hod_deleted = 1
            WHERE teacher_leave_id = ?
              AND hod_id = ?
              AND hod_deleted = 0
              AND status IN {allowed_statuses}
              AND teacher_id IN (
                  SELECT teacher_id FROM teachers WHERE department = ?
              )
        """, (leave_id, hod_id, department))
        target = "/hod_dashboard"
    else:
        cursor.execute(f"""
            UPDATE leave_requests
            SET hod_deleted = 1
            WHERE leave_id = ?
              AND hod_id = ?
              AND hod_deleted = 0
              AND status IN {allowed_statuses}
              AND student_id IN (
                  SELECT student_id FROM students WHERE department = ?
              )
        """, (leave_id, hod_id, department))
        target = "/hod_dashboard"

    connection.commit()
    connection.close()
    flash("Leave request deleted from your HOD history")
    return auth_redirect(target, "hod", hod_id)


@app.route("/hod_delete_leave_request", methods=["POST"])
def hod_delete_leave_request_legacy():
    """Compatibility route for older POST forms."""
    role, hod_id = current_user()
    if role != "hod" or not hod_id:
        return flask_redirect("/hod_login")

    request_type = request.form.get("request_type", "student")
    leave_id = request.form.get("leave_id")
    if request_type not in {"student", "teacher"} or not leave_id:
        return auth_redirect("/hod_dashboard", "hod", hod_id)

    token = make_hod_leave_action_token(hod_id)
    location = f"/hod_delete_leave_request/{request_type}/{urllib.parse.quote(str(leave_id))}/{token}"
    return flask_redirect(_attach_messages(location))


# =========================================================
# NOTIFICATION ROUTES
# =========================================================

@app.route("/notifications")
def notifications():
    role, user_id = current_user()
    if not role:
        return redirect("/")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    items = []
    if role != "admin":
        # Only non-admin roles receive notifications. Admin has sent history only.
        cursor.execute("""
            UPDATE notification_recipients
            SET is_read = 1, read_at = CURRENT_TIMESTAMP
            WHERE recipient_role = ?
            AND recipient_user_id = ?
            AND deleted_at IS NULL
            AND is_read = 0
        """, (role, user_id))
        connection.commit()

        cursor.execute("""
            SELECT notification_recipients.recipient_id,
                   notifications.notification_id,
                   notifications.sender_role,
                   notifications.title,
                   notifications.message,
                   notifications.target_scope,
                   notifications.department,
                   notifications.semester,
                   notifications.created_at,
                   notification_recipients.is_read
            FROM notification_recipients
            JOIN notifications
              ON notifications.notification_id = notification_recipients.notification_id
            WHERE notification_recipients.recipient_role = ?
              AND notification_recipients.recipient_user_id = ?
              AND notification_recipients.deleted_at IS NULL
            ORDER BY notifications.notification_id DESC
        """, (role, user_id))
        items = cursor.fetchall()

    # Senders have their own independent history. Deleting a sent item hides
    # it only from the sender; recipient copies remain untouched.
    cursor.execute("""
        SELECT notifications.notification_id,
               notifications.title,
               notifications.message,
               notifications.target_scope,
               notifications.department,
               notifications.semester,
               notifications.created_at,
               COUNT(notification_recipients.recipient_id) AS recipient_count
        FROM notifications
        LEFT JOIN notification_recipients
          ON notification_recipients.notification_id = notifications.notification_id
        WHERE notifications.sender_role = ?
          AND notifications.sender_id = ?
          AND notifications.sender_deleted = 0
        GROUP BY notifications.notification_id
        ORDER BY notifications.notification_id DESC
    """, (role, user_id))
    sent_items = cursor.fetchall()
    connection.close()

    return render_template(
        "notifications.html",
        notifications=items,
        sent_notifications=sent_items,
        role=role
    )


@app.route("/notifications/unread_count")
def notification_unread_count():
    role, user_id = current_user()
    if not role:
        return {"count": 0}

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute("""
        SELECT COUNT(*)
        FROM notification_recipients
        WHERE recipient_role = ?
          AND recipient_user_id = ?
          AND deleted_at IS NULL
          AND is_read = 0
    """, (role, user_id))
    count = cursor.fetchone()[0]
    connection.close()
    return {"count": count}


@app.route("/delete_notification", methods=["POST"])
def delete_notification():
    role, user_id = current_user()
    if not role:
        return redirect("/")

    recipient_id = request.form.get("recipient_id")
    if not recipient_id:
        return redirect("/notifications")

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute("""
        UPDATE notification_recipients
        SET deleted_at = CURRENT_TIMESTAMP
        WHERE recipient_id = ?
          AND recipient_role = ?
          AND recipient_user_id = ?
          AND deleted_at IS NULL
    """, (recipient_id, role, user_id))
    connection.commit()
    connection.close()
    return redirect("/notifications")


@app.route("/delete_sent_notification", methods=["POST"])
def delete_sent_notification():
    role, user_id = current_user()
    if role not in ("admin", "hod", "teacher"):
        return redirect(notification_role_home(role))

    notification_id = request.form.get("notification_id")
    if not notification_id:
        return redirect("/notifications")

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute("""
        UPDATE notifications
        SET sender_deleted = 1
        WHERE notification_id = ?
          AND sender_role = ?
          AND sender_id = ?
          AND sender_deleted = 0
    """, (notification_id, role, user_id))
    if cursor.rowcount == 0:
        connection.close()
        flash("Notification was not found in your Sent Notifications history")
        return redirect("/notifications")

    connection.commit()
    connection.close()
    flash("Notification deleted from your Sent Notifications history")
    return redirect("/notifications")


@app.route("/notification_compose")
def notification_compose():
    role, user_id = current_user()
    if role not in ("admin", "hod", "teacher"):
        return redirect(notification_role_home(role))

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    departments = []
    semesters = []
    subjects = []
    department = None

    if role == "admin":
        cursor.execute("SELECT department_name FROM departments ORDER BY department_name")
        departments = cursor.fetchall()
    elif role == "hod":
        cursor.execute("""
            SELECT hods.department, teachers.department AS teacher_department
            FROM hods LEFT JOIN teachers ON hods.teacher_id = teachers.teacher_id
            WHERE hods.hod_id = ?
        """, (user_id,))
        row = cursor.fetchone()
        if row:
            department = row["teacher_department"] or row["department"]
    else:
        cursor.execute("SELECT department FROM teachers WHERE teacher_id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            department = row["department"]
            cursor.execute("""
                SELECT DISTINCT subjects.semester
                FROM teacher_subjects
                JOIN subjects ON subjects.subject_id = teacher_subjects.subject_id
                WHERE teacher_subjects.teacher_id = ?
                ORDER BY subjects.semester
            """, (user_id,))
            semesters = cursor.fetchall()
            cursor.execute("""
                SELECT subjects.subject_id, subjects.subject_name, subjects.semester
                FROM teacher_subjects
                JOIN subjects ON subjects.subject_id = teacher_subjects.subject_id
                WHERE teacher_subjects.teacher_id = ?
                ORDER BY subjects.semester, subjects.subject_name
            """, (user_id,))
            subjects = cursor.fetchall()

    connection.close()
    return render_template(
        "notification_compose.html",
        role=role,
        department=department,
        departments=departments,
        semesters=semesters,
        subjects=subjects
    )


@app.route("/create_notification", methods=["POST"])
def create_notification_route():
    role, user_id = current_user()
    if role not in ("admin", "hod", "teacher"):
        return redirect(notification_role_home(role))

    title = request.form.get("title", "").strip()
    message = request.form.get("message", "").strip()
    if not title or not message:
        flash("Notification title and message are required")
        return redirect("/notification_compose")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    target_scope = ""
    department = None
    semester = None

    if role == "admin":
        target_scope = request.form.get("target_scope", "college")
        if target_scope == "department":
            department = request.form.get("department", "").strip()
            if not department:
                connection.close()
                flash("Select a department")
                return redirect("/notification_compose")
        elif target_scope != "college":
            connection.close()
            flash("Invalid notification target")
            return redirect("/notification_compose")

        recipients = []
        if target_scope == "college":
            recipients = get_notification_recipients(cursor, "admin")
        else:
            for row in cursor.execute("SELECT student_id FROM students WHERE department = ?", (department,)).fetchall():
                recipients.append(("student", row[0]))
            for row in cursor.execute("SELECT teacher_id FROM teachers WHERE department = ?", (department,)).fetchall():
                recipients.append(("teacher", row[0]))
            for row in cursor.execute("SELECT hod_id FROM hods WHERE department = ?", (department,)).fetchall():
                recipients.append(("hod", row[0]))

    elif role == "hod":
        target_scope = "department"
        cursor.execute("""
            SELECT hods.department, teachers.department AS teacher_department
            FROM hods LEFT JOIN teachers ON hods.teacher_id = teachers.teacher_id
            WHERE hods.hod_id = ?
        """, (user_id,))
        hod = cursor.fetchone()
        if not hod:
            connection.close()
            return redirect("/hod_login")
        department = hod["teacher_department"] or hod["department"]
        recipients = get_notification_recipients(cursor, "hod", department=department)

    else:
        target_scope = "semester"
        cursor.execute("SELECT department FROM teachers WHERE teacher_id = ?", (user_id,))
        teacher = cursor.fetchone()
        if not teacher:
            connection.close()
            return redirect("/teacher_login")
        department = teacher["department"]
        try:
            semester = int(request.form.get("semester", ""))
        except ValueError:
            semester = None
        if not semester:
            connection.close()
            flash("Select a semester")
            return redirect("/notification_compose")
        recipients = get_notification_recipients(
            cursor, "teacher", department=department, semester=semester, teacher_id=user_id
        )

    if not recipients:
        connection.close()
        flash("There are no matching recipients for this notification")
        return redirect("/notification_compose")

    create_notification(
        connection, role, user_id, title, message,
        target_scope, department, semester, recipients
    )
    connection.commit()
    connection.close()
    flash("Notification sent successfully. It has been saved in your Sent Notifications history.")
    return redirect("/notifications")


# =========================================================
# ASSIGNMENT ROUTES
# =========================================================

@app.route("/assignments")
def assignments():
    if current_user()[0] != "student":
        return redirect("/student_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("""
        SELECT assignments.*, subjects.subject_name,
               teachers.name AS teacher_name,
               assignment_submissions.submission_id,
               assignment_submissions.submitted_at,
               CASE WHEN assignment_submissions.submission_id IS NULL THEN 0 ELSE 1 END AS submitted,
               CASE WHEN assignment_submissions.submission_id IS NULL AND datetime(assignments.due_date) < datetime('now') THEN 1 ELSE 0 END AS overdue
        FROM assignments
        JOIN subjects ON subjects.subject_id = assignments.subject_id
        JOIN teachers ON teachers.teacher_id = assignments.teacher_id
        JOIN students ON students.student_id = ?
        JOIN student_subjects ON student_subjects.subject_id = assignments.subject_id
                           AND student_subjects.student_id = students.student_id
        LEFT JOIN assignment_submissions
          ON assignment_submissions.assignment_id = assignments.assignment_id
         AND assignment_submissions.student_id = ?
        WHERE student_subjects.student_id = ?
          AND students.semester = assignments.semester
        ORDER BY assignments.semester, assignments.due_date DESC, assignments.assignment_id DESC
    """, (current_user()[1], current_user()[1], current_user()[1]))
    assignment_rows = cursor.fetchall()
    connection.close()
    return render_template("assignments.html", assignments=assignment_rows, role="student")


@app.route("/assignment/<int:assignment_id>")
def assignment_detail(assignment_id):
    if current_user()[0] != "student":
        return redirect("/student_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("""
        SELECT assignments.*, subjects.subject_name, teachers.name AS teacher_name,
               students.department AS student_department, students.semester AS student_semester,
               assignment_submissions.submission_id, assignment_submissions.file_name,
               assignment_submissions.submitted_at
        FROM assignments
        JOIN subjects ON subjects.subject_id = assignments.subject_id
        JOIN teachers ON teachers.teacher_id = assignments.teacher_id
        JOIN students ON students.student_id = ?
        LEFT JOIN assignment_submissions
          ON assignment_submissions.assignment_id = assignments.assignment_id
         AND assignment_submissions.student_id = students.student_id
        WHERE assignments.assignment_id = ?
          AND students.department = subjects.department
          AND students.semester = assignments.semester
          AND EXISTS (
              SELECT 1 FROM student_subjects ss
              WHERE ss.student_id = students.student_id
                AND ss.subject_id = assignments.subject_id
          )
    """, (current_user()[1], assignment_id))
    assignment = cursor.fetchone()
    connection.close()
    if not assignment:
        flash("Assignment not found or not assigned to you")
        return redirect("/assignments")
    return render_template("assignment_detail.html", assignment=assignment, role="student")


@app.route("/submit_assignment", methods=["POST"])
def submit_assignment():
    if current_user()[0] != "student":
        return redirect("/student_login")

    assignment_id = request.form.get("assignment_id")
    uploaded = request.files.get("assignment_file")
    if not assignment_id or not uploaded or not uploaded.filename:
        flash("Please select a PDF file")
        return redirect(f"/assignment/{assignment_id}")

    filename = secure_filename(uploaded.filename)
    if not filename.lower().endswith(".pdf"):
        flash("Only PDF files are accepted")
        return redirect(f"/assignment/{assignment_id}")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("""
        SELECT assignments.assignment_id, assignments.teacher_id, assignments.subject_id,
               assignments.semester, assignments.due_date, subjects.department
        FROM assignments
        JOIN subjects ON subjects.subject_id = assignments.subject_id
        JOIN students ON students.student_id = ?
        WHERE assignments.assignment_id = ?
          AND students.department = subjects.department
          AND students.semester = assignments.semester
          AND EXISTS (
              SELECT 1 FROM student_subjects ss
              WHERE ss.student_id = students.student_id AND ss.subject_id = assignments.subject_id
          )
    """, (current_user()[1], assignment_id))
    assignment = cursor.fetchone()
    if not assignment:
        connection.close()
        flash("You are not allowed to submit this assignment")
        return redirect("/assignments")

    student_folder = os.path.join(UPLOAD_FOLDER, str(assignment_id))
    os.makedirs(student_folder, exist_ok=True)
    stored_name = f"{current_user()[1]}_{filename}"
    stored_path = os.path.join(student_folder, stored_name)
    uploaded.save(stored_path)

    cursor.execute("""
        SELECT submission_id FROM assignment_submissions
        WHERE assignment_id = ? AND student_id = ?
    """, (assignment_id, current_user()[1]))
    existing = cursor.fetchone()
    relative_path = os.path.relpath(stored_path, "static").replace("\\", "/")
    if existing:
        cursor.execute("""
            UPDATE assignment_submissions
            SET file_name = ?, stored_path = ?, submitted_at = CURRENT_TIMESTAMP
            WHERE submission_id = ?
        """, (filename, relative_path, existing["submission_id"]))
    else:
        cursor.execute("""
            INSERT INTO assignment_submissions
            (assignment_id, student_id, file_name, stored_path)
            VALUES (?, ?, ?, ?)
        """, (assignment_id, current_user()[1], filename, relative_path))

    connection.commit()
    connection.close()
    flash("Assignment submitted successfully")
    return redirect(f"/assignment/{assignment_id}")


@app.route("/teacher_assignments")
def teacher_assignments():
    if current_user()[0] != "teacher":
        return redirect("/teacher_login")

    teacher_id = current_user()[1]
    selected_semester = request.args.get("semester", "")
    selected_subject = request.args.get("subject_id", "")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("SELECT department FROM teachers WHERE teacher_id = ?", (teacher_id,))
    teacher = cursor.fetchone()
    if not teacher:
        connection.close()
        return redirect("/teacher_login")

    cursor.execute("""
        SELECT subjects.subject_id, subjects.subject_name, subjects.semester
        FROM teacher_subjects
        JOIN subjects ON subjects.subject_id = teacher_subjects.subject_id
        WHERE teacher_subjects.teacher_id = ?
        ORDER BY subjects.semester, subjects.subject_name
    """, (teacher_id,))
    subjects = cursor.fetchall()

    query = """
        SELECT assignments.*, subjects.subject_name,
               COUNT(DISTINCT assignment_submissions.submission_id) AS submitted_count,
               (SELECT COUNT(*) FROM students s
                WHERE s.department = subjects.department
                  AND s.semester = assignments.semester
                  AND EXISTS (SELECT 1 FROM student_subjects ss
                              WHERE ss.student_id = s.student_id AND ss.subject_id = assignments.subject_id)) AS student_count
        FROM assignments
        JOIN subjects ON subjects.subject_id = assignments.subject_id
        LEFT JOIN assignment_submissions ON assignment_submissions.assignment_id = assignments.assignment_id
        WHERE assignments.teacher_id = ?
    """
    params = [teacher_id]
    if selected_semester:
        query += " AND assignments.semester = ?"
        params.append(selected_semester)
    if selected_subject:
        query += " AND assignments.subject_id = ?"
        params.append(selected_subject)
    query += " GROUP BY assignments.assignment_id ORDER BY assignments.semester, assignments.due_date DESC, assignments.assignment_id DESC"
    cursor.execute(query, params)
    assignment_rows = cursor.fetchall()

    semesters = sorted({row["semester"] for row in subjects})
    connection.close()
    return render_template(
        "teacher_assignments.html",
        teacher=teacher,
        subjects=subjects,
        semesters=semesters,
        assignments=assignment_rows,
        selected_semester=selected_semester,
        selected_subject=selected_subject,
        role="teacher"
    )


@app.route("/create_assignment", methods=["POST"])
def create_assignment():
    if current_user()[0] != "teacher":
        return redirect("/teacher_login")

    teacher_id = current_user()[1]
    subject_id = request.form.get("subject_id", "").strip()
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    due_date = request.form.get("due_date", "").strip()
    if not subject_id or not title or not description or not due_date:
        flash("All assignment fields are required")
        return redirect("/teacher_assignments")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("""
        SELECT subjects.subject_id, subjects.subject_name, subjects.department, subjects.semester
        FROM teacher_subjects
        JOIN subjects ON subjects.subject_id = teacher_subjects.subject_id
        WHERE teacher_subjects.teacher_id = ? AND subjects.subject_id = ?
    """, (teacher_id, subject_id))
    subject = cursor.fetchone()
    if not subject:
        connection.close()
        flash("You can create assignments only for your assigned subjects")
        return redirect("/teacher_assignments")

    try:
        datetime.strptime(due_date, "%Y-%m-%dT%H:%M")
    except ValueError:
        connection.close()
        flash("Please enter a valid due date and time")
        return redirect("/teacher_assignments")

    cursor.execute("""
        INSERT INTO assignments
        (teacher_id, subject_id, semester, title, description, due_date)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (teacher_id, subject_id, subject["semester"], title, description, due_date.replace("T", " ")))
    assignment_id = cursor.lastrowid

    recipients = []
    for row in cursor.execute("""
        SELECT DISTINCT students.student_id
        FROM students
        JOIN student_subjects ON student_subjects.student_id = students.student_id
        WHERE student_subjects.subject_id = ?
          AND students.department = ?
          AND students.semester = ?
    """, (subject_id, subject["department"], subject["semester"])).fetchall():
        recipients.append(("student", row[0]))

    if recipients:
        create_notification(
            connection, "teacher", teacher_id,
            f"New Assignment: {title}",
            f"A new assignment has been posted for {subject['subject_name']}. Due: {due_date.replace('T', ' ')}.",
            "assignment", subject["department"], subject["semester"], recipients
        )

    connection.commit()
    connection.close()
    flash("Assignment created and students notified")
    return redirect("/teacher_assignments")


@app.route("/teacher_assignment_submissions/<int:assignment_id>")
def teacher_assignment_submissions(assignment_id):
    if current_user()[0] != "teacher":
        return redirect("/teacher_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("""
        SELECT assignments.*, subjects.subject_name, subjects.department,
               teachers.name AS teacher_name
        FROM assignments
        JOIN subjects ON subjects.subject_id = assignments.subject_id
        JOIN teachers ON teachers.teacher_id = assignments.teacher_id
        WHERE assignments.assignment_id = ? AND assignments.teacher_id = ?
    """, (assignment_id, current_user()[1]))
    assignment = cursor.fetchone()
    if not assignment:
        connection.close()
        flash("Assignment not found")
        return redirect("/teacher_assignments")

    cursor.execute("""
        SELECT students.student_id, students.name, students.semester,
               assignment_submissions.submission_id,
               assignment_submissions.file_name,
               assignment_submissions.submitted_at
        FROM students
        JOIN student_subjects ON student_subjects.student_id = students.student_id
        LEFT JOIN assignment_submissions
          ON assignment_submissions.student_id = students.student_id
         AND assignment_submissions.assignment_id = ?
        WHERE student_subjects.subject_id = ?
          AND students.department = ?
          AND students.semester = ?
        ORDER BY students.name
    """, (assignment_id, assignment["subject_id"], assignment["department"], assignment["semester"]))
    students = cursor.fetchall()
    connection.close()
    return render_template("teacher_assignment_submissions.html", assignment=assignment, students=students, role="teacher")


@app.route("/delete_assignment", methods=["POST"])
def delete_assignment():
    if current_user()[0] != "teacher":
        return redirect("/teacher_login")

    teacher_id = current_user()[1]
    assignment_id = request.form.get("assignment_id")
    if not assignment_id:
        return redirect("/teacher_assignments")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    # A teacher may delete an assignment only after every student in that
    # assignment's class has submitted it.
    cursor.execute("""
        SELECT assignments.assignment_id, assignments.teacher_id,
               assignments.subject_id, assignments.semester,
               subjects.department,
               (SELECT COUNT(*) FROM students s
                WHERE s.department = subjects.department
                  AND s.semester = assignments.semester
                  AND EXISTS (SELECT 1 FROM student_subjects ss
                              WHERE ss.student_id = s.student_id
                                AND ss.subject_id = assignments.subject_id)) AS student_count,
               (SELECT COUNT(DISTINCT sub.student_id)
                FROM assignment_submissions sub
                WHERE sub.assignment_id = assignments.assignment_id) AS submitted_count
        FROM assignments
        JOIN subjects ON subjects.subject_id = assignments.subject_id
        WHERE assignments.assignment_id = ?
          AND assignments.teacher_id = ?
    """, (assignment_id, teacher_id))
    assignment = cursor.fetchone()

    if not assignment:
        connection.close()
        flash("Assignment not found")
        return redirect("/teacher_assignments")

    if assignment["student_count"] <= 0 or assignment["submitted_count"] < assignment["student_count"]:
        connection.close()
        flash("You can delete this assignment only after all students have submitted it")
        return redirect(f"/teacher_assignment_submissions/{assignment_id}")

    # Collect submitted file paths before removing the database rows.
    cursor.execute("""
        SELECT stored_path FROM assignment_submissions
        WHERE assignment_id = ?
    """, (assignment_id,))
    stored_files = [row["stored_path"] for row in cursor.fetchall() if row["stored_path"]]

    cursor.execute("DELETE FROM assignment_submissions WHERE assignment_id = ?", (assignment_id,))
    cursor.execute("DELETE FROM assignments WHERE assignment_id = ? AND teacher_id = ?", (assignment_id, teacher_id))

    connection.commit()
    connection.close()

    # Remove uploaded PDFs belonging to this assignment from disk as well.
    for stored_path in stored_files:
        try:
            absolute_file = os.path.join(BASE_DIR, "static", stored_path)
            if os.path.isfile(absolute_file):
                os.remove(absolute_file)
        except OSError:
            pass

    assignment_folder = os.path.join(UPLOAD_FOLDER, str(assignment_id))
    try:
        if os.path.isdir(assignment_folder) and not os.listdir(assignment_folder):
            os.rmdir(assignment_folder)
    except OSError:
        pass

    flash("Assignment and all submitted PDFs were deleted")
    return redirect("/teacher_assignments")


@app.route("/assignment_file/<int:submission_id>")
def assignment_file(submission_id):
    role, user_id = current_user()
    if role not in ("student", "teacher"):
        return redirect("/")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("""
        SELECT assignment_submissions.*, assignments.teacher_id, assignments.subject_id,
               students.student_id
        FROM assignment_submissions
        JOIN assignments ON assignments.assignment_id = assignment_submissions.assignment_id
        JOIN students ON students.student_id = assignment_submissions.student_id
        WHERE assignment_submissions.submission_id = ?
    """, (submission_id,))
    submission = cursor.fetchone()
    connection.close()
    if not submission:
        return "File not found", 404
    if role == "student" and submission["student_id"] != user_id:
        return "Unauthorized", 403
    if role == "teacher" and submission["teacher_id"] != user_id:
        return "Unauthorized", 403

    absolute_path = os.path.join("static", submission["stored_path"])
    folder = os.path.dirname(absolute_path)
    filename = os.path.basename(absolute_path)
    return send_from_directory(folder, filename, as_attachment=True)


@app.route("/send_assignment_warning", methods=["POST"])
def send_assignment_warning():
    if current_user()[0] != "teacher":
        return redirect("/teacher_login")

    assignment_id = request.form.get("assignment_id")
    student_id = request.form.get("student_id")
    if not assignment_id or not student_id:
        return redirect("/teacher_assignments")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("""
        SELECT assignments.title, assignments.due_date, subjects.subject_name,
               assignments.subject_id, assignments.semester, subjects.department
        FROM assignments
        JOIN subjects ON subjects.subject_id = assignments.subject_id
        WHERE assignments.assignment_id = ? AND assignments.teacher_id = ?
    """, (assignment_id, current_user()[1]))
    assignment = cursor.fetchone()
    cursor.execute("""
        SELECT students.student_id
        FROM students
        JOIN student_subjects ON student_subjects.student_id = students.student_id
        WHERE students.student_id = ?
          AND student_subjects.subject_id = ?
          AND students.department = ?
          AND students.semester = ?
    """, (student_id, assignment["subject_id"] if assignment else "", assignment["department"] if assignment else "", assignment["semester"] if assignment else ""))
    valid_student = cursor.fetchone()
    if not assignment or not valid_student:
        connection.close()
        flash("Student is not part of this assignment's class")
        return redirect(f"/teacher_assignment_submissions/{assignment_id}")

    cursor.execute("""
        SELECT submission_id FROM assignment_submissions
        WHERE assignment_id = ? AND student_id = ?
    """, (assignment_id, student_id))
    if cursor.fetchone():
        connection.close()
        flash("This student has already submitted the assignment")
        return redirect(f"/teacher_assignment_submissions/{assignment_id}")

    create_notification(
        connection, "teacher", current_user()[1],
        "Assignment Submission Reminder",
        f"Please submit '{assignment['title']}' for {assignment['subject_name']} as soon as possible. Due: {assignment['due_date']}.",
        "assignment_warning", assignment["department"], assignment["semester"], [("student", student_id)]
    )
    connection.commit()
    connection.close()
    flash("Warning notification sent to the student")
    return redirect(f"/teacher_assignment_submissions/{assignment_id}")


# =========================================================
# ADMIN ROUTES
# =========================================================

@app.route("/admin_login")
def admin_login():
    return render_template("admin_login.html")


@app.route("/admin_login", methods=["POST"])
def admin_login_post():

    admin_id = request.form["admin_id"]
    password = request.form["password"]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
    SELECT *
    FROM admins
    WHERE admin_id = ?
    AND password = ?
    """, (admin_id, password))

    admin = cursor.fetchone()

    connection.close()

    if admin:
        return auth_redirect("/admin_dashboard", "admin", admin["admin_id"])

    else:

        flash("Invalid Admin ID or Password")

        return redirect("/admin_login")


@app.route("/admin_dashboard")
def admin_dashboard():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    # Get admin
    cursor.execute("""
        SELECT *
        FROM admins
        WHERE admin_id = ?
    """, (current_user()[1],))

    admin = cursor.fetchone()


    # Get departments
    cursor.execute("""
        SELECT DISTINCT department
        FROM students
        ORDER BY department
    """)

    student_departments = cursor.fetchall()


    # Get departments from subjects
    cursor.execute("""
        SELECT DISTINCT department
        FROM subjects
        ORDER BY department
    """)

    subject_departments = cursor.fetchall()


    # Get teacher counts by department
    cursor.execute("""
        SELECT department,
               COUNT(*) AS teacher_count
        FROM teachers
        GROUP BY department
        ORDER BY department
    """)

    teacher_departments = cursor.fetchall()


    connection.close()

    return render_template(
        "admin_dashboard.html",
        admin=admin,
        student_departments=student_departments,
        subject_departments=subject_departments,
        teacher_departments=teacher_departments
    )


@app.route("/admin_dashboard_count")
def admin_dashboard_count():

    if current_user()[0] != "admin":
        return {"error": "Unauthorized"}, 401

    department = request.args.get("department")
    semester = request.args.get("semester")

    if not department:
        return {
            "student_count": 0,
            "subject_count": 0,
            "teacher_count": 0
        }


    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()


    # -----------------------------------------------------
    # STUDENT COUNT
    # -----------------------------------------------------

    student_count = 0

    if semester:
        cursor.execute("""
            SELECT COUNT(*)
            FROM students
            WHERE department = ?
            AND semester = ?
        """, (
            department,
            semester
        ))

        student_count = cursor.fetchone()[0]


    # -----------------------------------------------------
    # SUBJECT COUNT
    # -----------------------------------------------------

    subject_count = 0

    if semester:
        cursor.execute("""
            SELECT COUNT(*)
            FROM subjects
            WHERE department = ?
            AND semester = ?
        """, (
            department,
            semester
        ))

        subject_count = cursor.fetchone()[0]


    # -----------------------------------------------------
    # TEACHER COUNT
    # -----------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*)
        FROM teachers
        WHERE department = ?
    """, (
        department,
    ))

    teacher_count = cursor.fetchone()[0]


    connection.close()


    return {
        "student_count": student_count,
        "subject_count": subject_count,
        "teacher_count": teacher_count
    }


@app.route("/admin_departments", methods=["GET", "POST"])
def admin_departments():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()


    # =====================================================
    # ADD DEPARTMENT
    # =====================================================

    if request.method == "POST":

        department_name = request.form["department"].strip()

        if not department_name:

            flash("Department name cannot be empty.")

        else:

            try:

                cursor.execute("""
                    INSERT INTO departments (department_name)
                    VALUES (?)
                """, (
                    department_name,
                ))

                connection.commit()

                flash("Department added successfully.")

            except sqlite3.IntegrityError:

                flash("Department already exists.")


    # =====================================================
    # GET ALL DEPARTMENTS
    # =====================================================

    cursor.execute("""
        SELECT *
        FROM departments
        ORDER BY department_name
    """)

    departments = cursor.fetchall()


    connection.close()


    return render_template(
        "admin_departments.html",
        departments=departments
    )


@app.route("/admin_delete_department", methods=["POST"])
def admin_delete_department():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    department_id = request.form["department_id"]


    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()


    cursor.execute("""
        DELETE FROM departments
        WHERE department_id = ?
    """, (
        department_id,
    ))


    connection.commit()

    connection.close()


    flash("Department deleted successfully.")

    return redirect("/admin_departments")


@app.route("/admin_students", methods=["GET", "POST"])
def admin_students():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    # Get all departments that have students
    cursor.execute("""
        SELECT DISTINCT department
        FROM students
        ORDER BY department
    """)

    departments = cursor.fetchall()

    # Get all semesters that have students
    cursor.execute("""
        SELECT DISTINCT semester
        FROM students
        ORDER BY semester
    """)

    semesters = cursor.fetchall()

    students = []

    selected_department = None
    selected_semester = None

    # If department and semester were selected
    if request.method == "POST":

        selected_department = request.form["department"]
        selected_semester = request.form["semester"]

        cursor.execute("""
            SELECT *
            FROM students
            WHERE department = ?
            AND semester = ?
            ORDER BY student_id
        """, (
            selected_department,
            selected_semester
        ))

        students = cursor.fetchall()

    connection.close()

    return render_template(
        "admin_students.html",
        students=students,
        departments=departments,
        semesters=semesters,
        selected_department=selected_department,
        selected_semester=selected_semester
    )


@app.route("/admin_add_student")
def admin_add_student():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    # Get departments from the departments table
    cursor.execute("""
        SELECT department_id, department_name
        FROM departments
        ORDER BY department_name
    """)

    departments = cursor.fetchall()

    connection.close()

    return render_template(
        "admin_add_student.html",
        departments=departments
    )


@app.route("/admin_add_student", methods=["POST"])
def admin_add_student_post():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    student_id = request.form["student_id"]
    password = request.form["password"]
    name = request.form["name"]
    department = request.form["department"]
    semester = request.form["semester"]
    email = request.form["email"]
    phone = request.form["phone"]

    # Server-side validation so invalid phone numbers cannot be submitted
    # even if browser-side validation is bypassed.
    if not phone.isdigit() or len(phone) != 10:
        flash("10 numbers must be entered")
        return redirect("/admin_add_student")

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    try:

        cursor.execute("""
        INSERT INTO students
        (student_id, password, name, department, semester, email, phone)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            student_id,
            password,
            name,
            department,
            semester,
            email,
            phone
        ))

        connection.commit()
        connection.close()

        flash("Student added successfully")

        return redirect("/admin_students")

    except sqlite3.IntegrityError:

        connection.close()

        flash("Student ID already exists")

        return redirect("/admin_add_student")


@app.route("/admin_delete_student", methods=["POST"])
def admin_delete_student():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    student_id = request.form["student_id"]

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # Delete student-subject enrollment records
    cursor.execute("""
    DELETE FROM student_subjects
    WHERE student_id = ?
    """, (student_id,))

    # Delete attendance records
    cursor.execute("""
    DELETE FROM attendance
    WHERE student_id = ?
    """, (student_id,))

    # Delete marks records
    cursor.execute("""
    DELETE FROM marks
    WHERE student_id = ?
    """, (student_id,))

    # Delete student
    cursor.execute("""
    DELETE FROM students
    WHERE student_id = ?
    """, (student_id,))

    connection.commit()
    connection.close()

    flash("Student deleted successfully")

    return redirect("/admin_students")


@app.route("/admin_teachers", methods=["GET", "POST"])
def admin_teachers():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    # Get available departments
    cursor.execute("""
    SELECT DISTINCT department
    FROM teachers
    ORDER BY department
    """)

    departments = cursor.fetchall()

    teachers = []

    selected_department = None

    # If admin selected a department
    if request.method == "POST":

        selected_department = request.form["department"]

        cursor.execute("""
        SELECT *
        FROM teachers
        WHERE department = ?
        ORDER BY teacher_id
        """, (
            selected_department,
        ))

        teachers = cursor.fetchall()

    connection.close()

    return render_template(
        "admin_teachers.html",
        teachers=teachers,
        departments=departments,
        selected_department=selected_department
    )


@app.route("/admin_add_teacher")
def admin_add_teacher():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    # Get departments from the departments table
    cursor.execute("""
        SELECT department_id, department_name
        FROM departments
        ORDER BY department_name
    """)

    departments = cursor.fetchall()

    connection.close()

    return render_template(
        "admin_add_teacher.html",
        departments=departments
    )


@app.route("/admin_add_teacher", methods=["POST"])
def admin_add_teacher_post():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    teacher_id = request.form["teacher_id"]
    password = request.form["password"]
    name = request.form["name"]
    department = request.form["department"]
    email = request.form["email"]
    phone = request.form["phone"]

    # Server-side validation so invalid phone numbers cannot be submitted
    # even if browser-side validation is bypassed.
    if not phone.isdigit() or len(phone) != 10:
        flash("10 numbers must be entered")
        return redirect("/admin_add_teacher")

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    try:

        cursor.execute("""
        INSERT INTO teachers
        (teacher_id, password, name, department, email, phone)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            teacher_id,
            password,
            name,
            department,
            email,
            phone
        ))

        connection.commit()
        connection.close()

        flash("Teacher added successfully")

        return redirect("/admin_teachers")

    except sqlite3.IntegrityError:

        connection.close()

        flash("Teacher ID already exists")

        return redirect("/admin_add_teacher")


@app.route("/admin_delete_teacher", methods=["POST"])
def admin_delete_teacher():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    teacher_id = request.form["teacher_id"]

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # Remove teacher-subject assignments
    cursor.execute("""
    DELETE FROM teacher_subjects
    WHERE teacher_id = ?
    """, (teacher_id,))

    # Delete teacher
    cursor.execute("""
    DELETE FROM teachers
    WHERE teacher_id = ?
    """, (teacher_id,))

    connection.commit()
    connection.close()

    flash("Teacher deleted successfully")

    return redirect("/admin_teachers")


@app.route("/admin_subjects", methods=["GET", "POST"])
def admin_subjects():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    # Get all departments that have subjects
    cursor.execute("""
        SELECT DISTINCT department
        FROM subjects
        ORDER BY department
    """)

    departments = cursor.fetchall()

    # Get all semesters that have subjects
    cursor.execute("""
        SELECT DISTINCT semester
        FROM subjects
        ORDER BY semester
    """)

    semesters = cursor.fetchall()

    subjects = []

    selected_department = None
    selected_semester = None

    # If department and semester were selected
    if request.method == "POST":

        selected_department = request.form["department"]
        selected_semester = request.form["semester"]

        cursor.execute("""
            SELECT *
            FROM subjects
            WHERE department = ?
            AND semester = ?
            ORDER BY subject_id
        """, (
            selected_department,
            selected_semester
        ))

        subjects = cursor.fetchall()

    connection.close()

    return render_template(
        "admin_subjects.html",
        subjects=subjects,
        departments=departments,
        semesters=semesters,
        selected_department=selected_department,
        selected_semester=selected_semester
    )


@app.route("/admin_add_subject")
def admin_add_subject():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    # Get departments from the departments table
    cursor.execute("""
        SELECT department_id, department_name
        FROM departments
        ORDER BY department_name
    """)

    departments = cursor.fetchall()

    connection.close()

    return render_template(
        "admin_add_subject.html",
        departments=departments
    )


@app.route("/admin_add_subject", methods=["POST"])
def admin_add_subject_post():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    subject_id = request.form["subject_id"]
    subject_name = request.form["subject_name"]
    department = request.form["department"]
    semester = request.form["semester"]
    subject_type = request.form["subject_type"]

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    try:

        cursor.execute("""
        INSERT INTO subjects
        (subject_id, subject_name, department, semester, subject_type)

        VALUES (?, ?, ?, ?, ?)
        """, (
            subject_id,
            subject_name,
            department,
            semester,
            subject_type
        ))

        connection.commit()
        connection.close()

        flash("Subject added successfully")

        return redirect("/admin_subjects")

    except sqlite3.IntegrityError:

        connection.close()

        flash("Subject ID already exists")

        return redirect("/admin_add_subject")


@app.route("/admin_delete_subject", methods=["POST"])
def admin_delete_subject():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    subject_id = request.form["subject_id"]

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # Delete student enrollments
    cursor.execute("""
    DELETE FROM student_subjects
    WHERE subject_id = ?
    """, (subject_id,))

    # Delete teacher assignments
    cursor.execute("""
    DELETE FROM teacher_subjects
    WHERE subject_id = ?
    """, (subject_id,))

    # Delete attendance records
    cursor.execute("""
    DELETE FROM attendance
    WHERE subject_id = ?
    """, (subject_id,))

    # Delete marks records
    cursor.execute("""
    DELETE FROM marks
    WHERE subject_id = ?
    """, (subject_id,))

    # Delete subject
    cursor.execute("""
    DELETE FROM subjects
    WHERE subject_id = ?
    """, (subject_id,))

    connection.commit()
    connection.close()

    flash("Subject deleted successfully")

    return redirect("/admin_subjects")


@app.route("/admin_enrollment", methods=["GET", "POST"])
def admin_enrollment():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    # Get departments
    cursor.execute("""
    SELECT DISTINCT department
    FROM students
    ORDER BY department
    """)

    departments = cursor.fetchall()


    # Get semesters
    cursor.execute("""
    SELECT DISTINCT semester
    FROM students
    ORDER BY semester
    """)

    semesters = cursor.fetchall()


    subjects = []

    selected_department = None
    selected_semester = None


    # If admin submitted department and semester
    if request.method == "POST":

        selected_department = request.form["department"]

        selected_semester = request.form["semester"]


        cursor.execute("""
        SELECT *
        FROM subjects
        WHERE department = ?
        AND semester = ?

        ORDER BY subject_name
        """, (
            selected_department,
            selected_semester
        ))

        subjects = cursor.fetchall()


    connection.close()


    return render_template(
        "admin_enrollment.html",

        departments=departments,

        semesters=semesters,

        subjects=subjects,

        selected_department=selected_department,

        selected_semester=selected_semester
    )


@app.route("/admin_enroll_students", methods=["POST"])
def admin_enroll_students():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    subject_id = request.form["subject_id"]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    # Get subject
    cursor.execute("""
    SELECT *
    FROM subjects
    WHERE subject_id = ?
    """, (subject_id,))

    subject = cursor.fetchone()

    if not subject:
        connection.close()

        flash("Subject not found")

        return redirect("/admin_enrollment")


    # Get all students from same department and semester
    cursor.execute("""
    SELECT student_id
    FROM students
    WHERE department = ?
    AND semester = ?
    """, (
        subject["department"],
        subject["semester"]
    ))

    students = cursor.fetchall()


    newly_enrolled = 0


    # Enroll matching students
    for student in students:

        student_id = student["student_id"]


        # Check whether student is already enrolled
        cursor.execute("""
        SELECT 1
        FROM student_subjects
        WHERE student_id = ?
        AND subject_id = ?
        """, (
            student_id,
            subject_id
        ))

        already_enrolled = cursor.fetchone()


        if already_enrolled:
            continue


        # Add student to subject
        cursor.execute("""
        INSERT INTO student_subjects
        (student_id, subject_id)

        VALUES (?, ?)
        """, (
            student_id,
            subject_id
        ))


        # Create attendance record
        cursor.execute("""
        INSERT OR IGNORE INTO attendance
        (student_id, subject_id, total_classes, present_classes)

        VALUES (?, ?, ?, ?)
        """, (
            student_id,
            subject_id,
            0,
            0
        ))


        # Create marks record
        cursor.execute("""
        INSERT OR IGNORE INTO marks
        (student_id, subject_id,
         internal_marks, external_marks, total_marks)

        VALUES (?, ?, ?, ?, ?)
        """, (
            student_id,
            subject_id,
            0,
            0,
            0
        ))


        newly_enrolled += 1


    connection.commit()
    connection.close()


    # Decide what message to show

    if newly_enrolled == 0:

        flash(
            f"All students are already enrolled in "
            f"{subject['subject_name']}."
        )

    else:

        flash(
            f"{newly_enrolled} students enrolled in "
            f"{subject['subject_name']} successfully."
        )

    return redirect("/admin_enrollment")


@app.route("/admin_teacher_subjects", methods=["GET", "POST"])
def admin_teacher_subjects():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    # Get departments
    cursor.execute("""
    SELECT DISTINCT department
    FROM teachers
    ORDER BY department
    """)

    departments = cursor.fetchall()

    teachers = []
    subjects = []
    assignments = []

    selected_department = None
    selected_semester = None

    # If admin selected department and semester
    if request.method == "POST":

        selected_department = request.form["department"]
        selected_semester = request.form["semester"]

        # Get teachers from selected department
        cursor.execute("""
        SELECT teacher_id, name, department
        FROM teachers
        WHERE department = ?
        ORDER BY name
        """, (
            selected_department,
        ))

        teachers = cursor.fetchall()

        # Get subjects from selected department + semester
        cursor.execute("""
        SELECT subject_id, subject_name, department, semester
        FROM subjects
        WHERE department = ?
        AND semester = ?
        ORDER BY subject_name
        """, (
            selected_department,
            selected_semester
        ))

        subjects = cursor.fetchall()

        # Get assignments for selected department + semester
        cursor.execute("""
        SELECT
            teacher_subjects.assignment_id,
            teachers.teacher_id,
            teachers.name AS teacher_name,
            subjects.subject_id,
            subjects.subject_name,
            subjects.semester

        FROM teacher_subjects

        JOIN teachers
            ON teacher_subjects.teacher_id = teachers.teacher_id

        JOIN subjects
            ON teacher_subjects.subject_id = subjects.subject_id

        WHERE subjects.department = ?
        AND subjects.semester = ?

        ORDER BY subjects.subject_name
        """, (
            selected_department,
            selected_semester
        ))

        assignments = cursor.fetchall()

    # Get semesters
    cursor.execute("""
    SELECT DISTINCT semester
    FROM subjects
    ORDER BY semester
    """)

    semesters = cursor.fetchall()

    connection.close()

    return render_template(
        "admin_teacher_subjects.html",

        departments=departments,
        semesters=semesters,

        teachers=teachers,
        subjects=subjects,
        assignments=assignments,

        selected_department=selected_department,
        selected_semester=selected_semester
    )


@app.route("/admin_assign_teacher_subject", methods=["POST"])
def admin_assign_teacher_subject():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    teacher_id = request.form["teacher_id"]
    subject_id = request.form["subject_id"]

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    # -------------------------------------------------
    # Get teacher
    # -------------------------------------------------

    cursor.execute("""
    SELECT teacher_id, name, department
    FROM teachers
    WHERE teacher_id = ?
    """, (teacher_id,))

    teacher = cursor.fetchone()

    if not teacher:
        connection.close()
        flash("Teacher not found")
        return redirect("/admin_teacher_subjects")


    # -------------------------------------------------
    # Get subject
    # -------------------------------------------------

    cursor.execute("""
    SELECT subject_id, subject_name, department, semester
    FROM subjects
    WHERE subject_id = ?
    """, (subject_id,))

    subject = cursor.fetchone()

    if not subject:
        connection.close()
        flash("Subject not found")
        return redirect("/admin_teacher_subjects")


    # -------------------------------------------------
    # Make sure teacher and subject belong together
    # -------------------------------------------------

    if teacher["department"] != subject["department"]:

        connection.close()

        flash(
            "Teacher and subject must belong to the same department"
        )

        return redirect("/admin_teacher_subjects")


    # -------------------------------------------------
    # Check whether this subject already has a teacher
    # -------------------------------------------------

    cursor.execute("""
    SELECT
        teacher_subjects.assignment_id,
        teachers.teacher_id,
        teachers.name
    FROM teacher_subjects

    JOIN teachers
        ON teacher_subjects.teacher_id = teachers.teacher_id

    WHERE teacher_subjects.subject_id = ?
    """, (subject_id,))

    existing_assignment = cursor.fetchone()


    # -------------------------------------------------
    # Same teacher already assigned
    # -------------------------------------------------

    if existing_assignment:

        if existing_assignment["teacher_id"] == teacher_id:

            connection.close()

            flash(
                f"{teacher['name']} is already assigned to "
                f"{subject['subject_name']}"
            )

            return redirect("/admin_teacher_subjects")

        # -------------------------------------------------
        # No existing teacher → create new assignment
        # -------------------------------------------------

        cursor.execute("""
        INSERT INTO teacher_subjects
        (teacher_id, subject_id)
        VALUES (?, ?)
        """, (
            teacher_id,
            subject_id
        ))

        connection.commit()
        connection.close()

        flash(
            f"{teacher['name']} assigned successfully to "
            f"{subject['subject_name']}"
        )

        return redirect("/admin_teacher_subjects")

        # -------------------------------------------------
        # Different teacher → replace old teacher
        # -------------------------------------------------

        cursor.execute("""
        UPDATE teacher_subjects

        SET teacher_id = ?

        WHERE subject_id = ?
        """, (
            teacher_id,
            subject_id
        ))

        connection.commit()
        connection.close()

        flash(
            f"Teacher changed successfully for "
            f"{subject['subject_name']}"
        )

        return redirect("/admin_teacher_subjects")


    # -------------------------------------------------
    # No teacher assigned yet → create assignment
    # -------------------------------------------------

    cursor.execute("""
    INSERT INTO teacher_subjects
    (teacher_id, subject_id)

    VALUES (?, ?)
    """, (
        teacher_id,
        subject_id
    ))

    connection.commit()
    connection.close()

    flash(
        f"{teacher['name']} assigned to "
        f"{subject['subject_name']} successfully"
    )

    return redirect("/admin_teacher_subjects")


@app.route("/admin_unassign_teacher_subject", methods=["POST"])
def admin_unassign_teacher_subject():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    assignment_id = request.form["assignment_id"]

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
    DELETE FROM teacher_subjects
    WHERE assignment_id = ?
    """, (assignment_id,))

    connection.commit()
    connection.close()

    flash("Teacher unassigned successfully")

    return redirect("/admin_teacher_subjects")


@app.route("/admin_hods", methods=["GET", "POST"])
def admin_hods():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
        SELECT department_id, department_name
        FROM departments
        ORDER BY department_name
    """)
    departments = cursor.fetchall()

    cursor.execute("""
        SELECT hods.hod_id, hods.password, hods.department, hods.teacher_id,
               teachers.name, teachers.email, teachers.phone
        FROM hods
        LEFT JOIN teachers ON hods.teacher_id = teachers.teacher_id
        ORDER BY hods.department
    """)
    hods = cursor.fetchall()
    connection.close()

    return render_template("admin_hods.html", departments=departments, hods=hods)


@app.route("/admin_hod_teachers")
def admin_hod_teachers():
    if current_user()[0] != "admin":
        return {"error": "Unauthorized"}, 401

    department = request.args.get("department", "").strip()
    if not department:
        return {"teachers": []}

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("""
        SELECT teacher_id, name, email, phone
        FROM teachers
        WHERE department = ?
          AND teacher_id NOT IN (SELECT COALESCE(teacher_id, '') FROM hods)
        ORDER BY name
    """, (department,))
    teachers = [dict(row) for row in cursor.fetchall()]
    connection.close()
    return {"teachers": teachers}


@app.route("/admin_add_hod", methods=["POST"])
def admin_add_hod():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    hod_id = request.form["hod_id"].strip()
    password = request.form["password"]
    department = request.form["department"].strip()
    teacher_id = request.form["teacher_id"].strip()

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM teachers WHERE teacher_id = ?", (teacher_id,))
    teacher = cursor.fetchone()

    if not teacher:
        connection.close()
        flash("Please select a valid teacher")
        return redirect("/admin_hods")

    if teacher["department"] != department:
        connection.close()
        flash("Selected teacher does not belong to the selected department")
        return redirect("/admin_hods")

    cursor.execute("SELECT hod_id FROM hods WHERE teacher_id = ?", (teacher_id,))
    if cursor.fetchone():
        connection.close()
        flash("This teacher is already assigned as an HOD")
        return redirect("/admin_hods")

    cursor.execute("SELECT hod_id FROM hods WHERE department = ?", (teacher["department"],))
    if cursor.fetchone():
        connection.close()
        flash("This department already has an HOD")
        return redirect("/admin_hods")

    try:
        cursor.execute("""
            INSERT INTO hods
            (hod_id, password, name, department, email, phone, teacher_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (hod_id, password, teacher["name"], teacher["department"], teacher["email"], teacher["phone"], teacher_id))
        connection.commit()
        connection.close()
        flash("HOD added successfully and linked to the selected teacher")
    except sqlite3.IntegrityError:
        connection.close()
        flash("HOD ID already exists")

    return redirect("/admin_hods")


@app.route("/admin_delete_hod", methods=["POST"])
def admin_delete_hod():

    if current_user()[0] != "admin":
        return redirect("/admin_login")

    hod_id = request.form["hod_id"]
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM leave_requests WHERE hod_id = ?", (hod_id,))
    student_history = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM teacher_leave_requests WHERE hod_id = ?", (hod_id,))
    teacher_history = cursor.fetchone()[0]

    if student_history + teacher_history > 0:
        connection.close()
        flash("This HOD cannot be deleted because leave request history is linked to the account")
        return redirect("/admin_hods")

    cursor.execute("DELETE FROM hods WHERE hod_id = ?", (hod_id,))
    connection.commit()
    connection.close()

    flash("HOD account deleted successfully. The teacher account remains unchanged.")
    return redirect("/admin_hods")

if __name__ == "__main__":
    app.run(debug=True)