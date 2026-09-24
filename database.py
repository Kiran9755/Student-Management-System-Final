import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "database", "university.db")
connection = sqlite3.connect(DATABASE)
cursor = connection.cursor()


# =====================================================
# STUDENTS
# =====================================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS students(
    student_id TEXT PRIMARY KEY,
    password TEXT,
    name TEXT,
    department TEXT,
    semester INTEGER,
    email TEXT,
    phone TEXT,
    leaves_taken INTEGER DEFAULT 0
)
""")


# =====================================================
# TEACHERS
# =====================================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS teachers(
    teacher_id TEXT PRIMARY KEY,
    password TEXT,
    name TEXT,
    department TEXT,
    email TEXT,
    phone TEXT,
    leaves_taken INTEGER DEFAULT 0
)
""")


# =====================================================
# ADMINS
# =====================================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS admins(
    admin_id TEXT PRIMARY KEY,
    password TEXT,
    name TEXT,
    email TEXT
)
""")

cursor.execute("""
INSERT OR IGNORE INTO admins
(admin_id, password, name, email)
VALUES (?, ?, ?, ?)
""", (
    "admin001",
    "admin123",
    "System Administrator",
    "admin@example.com"
))


# =====================================================
# DEPARTMENTS
# =====================================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS departments (
    department_id INTEGER PRIMARY KEY AUTOINCREMENT,
    department_name TEXT NOT NULL UNIQUE
)
""")


# =====================================================
# SUBJECTS
# =====================================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS subjects(
    subject_id TEXT PRIMARY KEY,
    subject_name TEXT,
    department TEXT,
    semester INTEGER,
    subject_type TEXT NOT NULL DEFAULT 'Theory'
)
""")


# =====================================================
# STUDENT SUBJECT ENROLLMENT
# =====================================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS student_subjects(
    enrollment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT,
    subject_id TEXT,
    FOREIGN KEY(student_id) REFERENCES students(student_id),
    FOREIGN KEY(subject_id) REFERENCES subjects(subject_id),
    UNIQUE(student_id, subject_id)
)
""")


# =====================================================
# TEACHER SUBJECT ASSIGNMENT
# =====================================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS teacher_subjects(
    assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    teacher_id TEXT,
    subject_id TEXT UNIQUE,
    FOREIGN KEY(teacher_id) REFERENCES teachers(teacher_id),
    FOREIGN KEY(subject_id) REFERENCES subjects(subject_id)
)
""")


# =====================================================
# ATTENDANCE
# =====================================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS attendance(
    attendance_id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT,
    subject_id TEXT,
    total_classes INTEGER DEFAULT 0,
    present_classes INTEGER DEFAULT 0,
    FOREIGN KEY(student_id) REFERENCES students(student_id),
    FOREIGN KEY(subject_id) REFERENCES subjects(subject_id),
    UNIQUE(student_id, subject_id)
)
""")


# =====================================================
# MARKS
# =====================================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS marks(
    mark_id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT,
    subject_id TEXT,
    internal_marks INTEGER DEFAULT 0,
    external_marks INTEGER DEFAULT 0,
    total_marks INTEGER DEFAULT 0,
    FOREIGN KEY(student_id) REFERENCES students(student_id),
    FOREIGN KEY(subject_id) REFERENCES subjects(subject_id),
    UNIQUE(student_id, subject_id)
)
""")


# =====================================================
# HOD ACCOUNTS
# =====================================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS hods(
    hod_id TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    department TEXT NOT NULL UNIQUE,
    email TEXT,
    phone TEXT,
    teacher_id TEXT UNIQUE,
    FOREIGN KEY(teacher_id) REFERENCES teachers(teacher_id)
)
""")


# =====================================================
# STUDENT LEAVE REQUESTS
# =====================================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS leave_requests(
    leave_id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT NOT NULL,
    hod_id TEXT,
    from_date TEXT NOT NULL,
    to_date TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending',
    hod_remark TEXT,
    applied_at TEXT DEFAULT CURRENT_TIMESTAMP,
    decided_at TEXT,
    FOREIGN KEY(student_id) REFERENCES students(student_id),
    FOREIGN KEY(hod_id) REFERENCES hods(hod_id)
)
""")


# =====================================================
# TEACHER LEAVE REQUESTS
# =====================================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS teacher_leave_requests(
    teacher_leave_id INTEGER PRIMARY KEY AUTOINCREMENT,
    teacher_id TEXT NOT NULL,
    hod_id TEXT,
    from_date TEXT NOT NULL,
    to_date TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending',
    hod_remark TEXT,
    applied_at TEXT DEFAULT CURRENT_TIMESTAMP,
    decided_at TEXT,
    FOREIGN KEY(teacher_id) REFERENCES teachers(teacher_id),
    FOREIGN KEY(hod_id) REFERENCES hods(hod_id)
)
""")



# =====================================================
# INDEPENDENT LEAVE-DELETION FLAGS
# =====================================================
def add_column_if_missing(table, column, definition):
    existing = [row[1] for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in existing:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

add_column_if_missing("leave_requests", "student_deleted", "INTEGER DEFAULT 0")
add_column_if_missing("leave_requests", "hod_deleted", "INTEGER DEFAULT 0")
add_column_if_missing("teacher_leave_requests", "teacher_deleted", "INTEGER DEFAULT 0")
add_column_if_missing("teacher_leave_requests", "hod_deleted", "INTEGER DEFAULT 0")


# =====================================================
# NOTIFICATIONS
# =====================================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS notifications(
    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_role TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    target_scope TEXT NOT NULL,
    department TEXT,
    semester INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    sender_deleted INTEGER DEFAULT 0
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS notification_recipients(
    recipient_id INTEGER PRIMARY KEY AUTOINCREMENT,
    notification_id INTEGER NOT NULL,
    recipient_role TEXT NOT NULL,
    recipient_user_id TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    read_at TEXT,
    deleted_at TEXT,
    FOREIGN KEY(notification_id) REFERENCES notifications(notification_id),
    UNIQUE(notification_id, recipient_role, recipient_user_id)
)
""")


# =====================================================
# ASSIGNMENTS
# =====================================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS assignments(
    assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    teacher_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    semester INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    due_date TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(teacher_id) REFERENCES teachers(teacher_id),
    FOREIGN KEY(subject_id) REFERENCES subjects(subject_id)
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS assignment_submissions(
    submission_id INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id INTEGER NOT NULL,
    student_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    submitted_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(assignment_id) REFERENCES assignments(assignment_id),
    FOREIGN KEY(student_id) REFERENCES students(student_id),
    UNIQUE(assignment_id, student_id)
)
""")

connection.commit()
connection.close()

print("University database created successfully!")
