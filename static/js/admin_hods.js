document.addEventListener("DOMContentLoaded", function () {
    const departmentSelect = document.getElementById("hod_department");
    const teacherSelect = document.getElementById("hod_teacher_id");
    if (!departmentSelect || !teacherSelect) return;

    function clearTeacherInfo() {
        document.getElementById("selected_teacher_name").textContent = "—";
        document.getElementById("selected_teacher_department").textContent = "—";
        document.getElementById("selected_teacher_email").textContent = "—";
        document.getElementById("selected_teacher_phone").textContent = "—";
    }

    departmentSelect.addEventListener("change", async function () {
        const department = this.value;
        teacherSelect.innerHTML = "<option value=''>Loading teachers...</option>";
        teacherSelect.disabled = true;
        clearTeacherInfo();

        if (!department) {
            teacherSelect.innerHTML = "<option value=''>First select a department</option>";
            return;
        }

        try {
            const response = await fetch(`/admin_hod_teachers?department=${encodeURIComponent(department)}`);
            const data = await response.json();
            teacherSelect.innerHTML = "<option value=''>Select Teacher</option>";

            if (!data.teachers.length) {
                teacherSelect.innerHTML = "<option value=''>No available teachers in this department</option>";
                return;
            }

            data.teachers.forEach(function (teacher) {
                const option = document.createElement("option");
                option.value = teacher.teacher_id;
                option.dataset.name = teacher.name || "";
                option.dataset.department = department;
                option.dataset.email = teacher.email || "";
                option.dataset.phone = teacher.phone || "";
                option.textContent = `${teacher.name} — ${teacher.teacher_id}`;
                teacherSelect.appendChild(option);
            });
            teacherSelect.disabled = false;
        } catch (error) {
            teacherSelect.innerHTML = "<option value=''>Unable to load teachers</option>";
        }
    });

    teacherSelect.addEventListener("change", function () {
        const option = this.options[this.selectedIndex];
        document.getElementById("selected_teacher_name").textContent = option.dataset.name || "—";
        document.getElementById("selected_teacher_department").textContent = option.dataset.department || "—";
        document.getElementById("selected_teacher_email").textContent = option.dataset.email || "—";
        document.getElementById("selected_teacher_phone").textContent = option.dataset.phone || "—";
    });
});
