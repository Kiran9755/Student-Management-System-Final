document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("input[data-phone-validation]").forEach(function (phoneInput) {
        const errorId = phoneInput.dataset.errorTarget;
        const errorElement = errorId ? document.getElementById(errorId) : null;
        const form = phoneInput.closest("form");

        function validatePhone(showMessage = true) {
            phoneInput.value = phoneInput.value.replace(/\D/g, "").slice(0, 10);
            const valid = phoneInput.value.length === 10;

            if (errorElement) {
                errorElement.textContent = valid ? "" : (showMessage ? "10 numbers must be entered" : "");
            }
            phoneInput.setCustomValidity(valid ? "" : "10 numbers must be entered");
            return valid;
        }

        phoneInput.addEventListener("input", function () {
            validatePhone(true);
        });

        if (form) {
            form.addEventListener("submit", function (event) {
                if (!validatePhone(true)) {
                    event.preventDefault();
                    phoneInput.reportValidity();
                }
            });
        }
    });
});
