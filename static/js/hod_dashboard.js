document.addEventListener("DOMContentLoaded", function () {
    function escapeHtml(value) {
        return String(value ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    async function loadHodData(type, semester, targetId) {
        const target = document.getElementById(targetId);
        if (!semester) {
            target.innerHTML = '<div class="teacher_leave_empty">Select a semester to view ' + (type === 'students' ? 'students' : 'subjects') + '.</div>';
            return;
        }

        target.innerHTML = '<div class="teacher_leave_empty">Loading...</div>';
        try {
            const response = await fetch(`/hod_dashboard_data?type=${type}&semester=${encodeURIComponent(semester)}`);
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || "Request failed");

            if (!data.items.length) {
                target.innerHTML = '<div class="teacher_leave_empty">No ' + (type === 'students' ? 'students' : 'subjects') + ' found in Semester ' + escapeHtml(semester) + '.</div>';
                return;
            }

            if (type === "students") {
                target.innerHTML = `<table class="teacher_leave_table"><thead><tr><th>Student ID</th><th>Name</th><th>Semester</th><th>Email</th><th>Phone</th></tr></thead><tbody>${data.items.map(student => `<tr><td>${escapeHtml(student.student_id)}</td><td><strong>${escapeHtml(student.name)}</strong></td><td>${escapeHtml(student.semester)}</td><td>${escapeHtml(student.email)}</td><td>${escapeHtml(student.phone || "—")}</td></tr>`).join("")}</tbody></table>`;
            } else {
                target.innerHTML = `<table class="teacher_leave_table"><thead><tr><th>Subject ID</th><th>Subject</th><th>Semester</th><th>Type</th></tr></thead><tbody>${data.items.map(subject => `<tr><td>${escapeHtml(subject.subject_id)}</td><td><strong>${escapeHtml(subject.subject_name)}</strong></td><td>${escapeHtml(subject.semester)}</td><td>${escapeHtml(subject.subject_type)}</td></tr>`).join("")}</tbody></table>`;
            }
        } catch (error) {
            target.innerHTML = '<div class="teacher_leave_empty">Unable to load data. Please try again.</div>';
        }
    }

    const studentSemester = document.getElementById("student_semester");
    const subjectSemester = document.getElementById("subject_semester");
    if (studentSemester) studentSemester.addEventListener("change", function () { loadHodData("students", this.value, "student_results"); });
    if (subjectSemester) subjectSemester.addEventListener("change", function () { loadHodData("subjects", this.value, "subject_results"); });
});
