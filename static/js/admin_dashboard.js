document.addEventListener("DOMContentLoaded", function () {
    const studentDepartment = document.getElementById("student_department");
    const studentSemester = document.getElementById("student_semester");
    const subjectDepartment = document.getElementById("subject_department");
    const subjectSemester = document.getElementById("subject_semester");
    const teacherDepartment = document.getElementById("teacher_department");

    if (!studentDepartment || !studentSemester || !subjectDepartment || !subjectSemester || !teacherDepartment) return;

    async function updateDashboardCount() {
        if (studentDepartment.value && studentSemester.value) {
            const response = await fetch(`/admin_dashboard_count?department=${encodeURIComponent(studentDepartment.value)}&semester=${studentSemester.value}`);
            const data = await response.json();
            document.getElementById("student_count").textContent = data.student_count;
        } else {
            document.getElementById("student_count").textContent = "0";
        }

        if (subjectDepartment.value && subjectSemester.value) {
            const response = await fetch(`/admin_dashboard_count?department=${encodeURIComponent(subjectDepartment.value)}&semester=${subjectSemester.value}`);
            const data = await response.json();
            document.getElementById("subject_count").textContent = data.subject_count;
        } else {
            document.getElementById("subject_count").textContent = "0";
        }

        if (teacherDepartment.value) {
            const response = await fetch(`/admin_dashboard_count?department=${encodeURIComponent(teacherDepartment.value)}`);
            const data = await response.json();
            document.getElementById("teacher_count").textContent = data.teacher_count;
        } else {
            document.getElementById("teacher_count").textContent = "0";
        }
    }

    [studentDepartment, studentSemester, subjectDepartment, subjectSemester, teacherDepartment]
        .forEach(function (element) { element.addEventListener("change", updateDashboardCount); });
});
