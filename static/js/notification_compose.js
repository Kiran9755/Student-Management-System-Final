document.addEventListener("DOMContentLoaded", function () {
    const target = document.getElementById("notification_target");
    const departmentWrap = document.getElementById("notification_department_wrap");

    function syncDepartmentVisibility() {
        if (target && departmentWrap) {
            departmentWrap.style.display = target.value === "department" ? "flex" : "none";
        }
    }

    if (target) {
        target.addEventListener("change", syncDepartmentVisibility);
        syncDepartmentVisibility();
    }
});
