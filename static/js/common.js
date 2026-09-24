/*
   Stateless tab-isolated navigation.
   Login identity is carried by signed URL parameters.
   Each login receives a signed role/id/token in its URL. This script keeps
   those three values attached to links, forms and fetch requests so every
   browser tab can stay logged in as a different role at the same time.
*/
(function () {
    const params = new URLSearchParams(window.location.search);
    const auth = {
        role: params.get("role"),
        id: params.get("id"),
        token: params.get("token")
    };

    function isValidAuth() {
        return !!(auth.role && auth.id && auth.token);
    }

    function withAuth(url) {
        if (!isValidAuth() || !url || !url.startsWith("/")) return url;
        if (url.startsWith("/static/") || url === "/" ||
            url.startsWith("/student_login") || url.startsWith("/teacher_login") ||
            url.startsWith("/hod_login") || url.startsWith("/admin_login")) return url;

        const hashIndex = url.indexOf("#");
        const hash = hashIndex >= 0 ? url.slice(hashIndex) : "";
        const clean = hashIndex >= 0 ? url.slice(0, hashIndex) : url;
        const queryIndex = clean.indexOf("?");
        const path = queryIndex >= 0 ? clean.slice(0, queryIndex) : clean;
        const query = queryIndex >= 0 ? clean.slice(queryIndex + 1) : "";
        const existing = new URLSearchParams(query);
        existing.delete("role");
        existing.delete("id");
        existing.delete("token");
        const authQuery = new URLSearchParams(auth);
        authQuery.forEach((value, key) => existing.set(key, value));
        const finalQuery = existing.toString();
        return path + (finalQuery ? "?" + finalQuery : "") + hash;
    }

    function attachAuthToForm(form) {
        if (!isValidAuth() || !form) return;
        const action = form.getAttribute("action") || window.location.pathname;
        if (action.startsWith("/")) {
            form.setAttribute("action", withAuth(action));
        }

        // Also include auth in POST form data. This is a second, robust path
        // for destructive actions if the browser submits before a rewritten
        // action URL is available.
        [
            ["role", auth.role],
            ["id", auth.id],
            ["token", auth.token]
        ].forEach(function ([name, value]) {
            let input = form.querySelector('input[type="hidden"][data-auth-field="' + name + '"]');
            if (!input) {
                input = document.createElement("input");
                input.type = "hidden";
                input.name = name;
                input.dataset.authField = name;
                form.appendChild(input);
            }
            input.value = value;
        });
    }

    // Make every normal link tab-safe.
    document.addEventListener("DOMContentLoaded", function () {
        document.querySelectorAll('a[href^="/"]').forEach(function (link) {
            const href = link.getAttribute("href");
            link.setAttribute("href", withAuth(href));
        });

        // Make every form tab-safe, including POST forms.
        document.querySelectorAll("form").forEach(function (form) {
            attachAuthToForm(form);
        });

        document.addEventListener("submit", function (event) {
            const form = event.target;
            attachAuthToForm(form);
            const submitter = event.submitter;
            const message = form.dataset.confirm || (submitter && submitter.dataset.confirm);
            if (message && !window.confirm(message)) {
                event.preventDefault();
            }
        });

        // Add the notification bell to every existing role navbar.
        const nav = document.querySelector(".global_nav_right");
        if (!nav || nav.querySelector(".notification_bell_link")) return;

        const home = nav.querySelector(".global_home_link");
        const href = home ? home.getAttribute("href") || "" : "";
        let role = auth.role || "";
        if (!role) {
            if (href.includes("admin_dashboard")) role = "admin";
            else if (href.includes("hod_dashboard")) role = "hod";
            else if (href.includes("teacher_dashboard")) role = "teacher";
            else if (href.includes("dashboard")) role = "student";
        }

        const bell = document.createElement("a");
        bell.className = "notification_bell_link";
        bell.href = withAuth("/notifications");
        bell.setAttribute("aria-label", "Notifications");
        bell.innerHTML = '<span class="notification_bell_icon">🔔</span><span class="notification_badge" hidden>0</span>';
        nav.insertBefore(bell, nav.firstChild);

        const menu = nav.querySelector(".global_nav_dropdown_menu");
        if (menu) {
            if (!menu.querySelector('a[href^="/notifications"]')) {
                const notificationLink = document.createElement("a");
                notificationLink.href = withAuth("/notifications");
                notificationLink.textContent = "Notifications";
                menu.insertBefore(notificationLink, menu.firstChild);
            }
            if (["admin", "hod", "teacher"].includes(role) && !menu.querySelector('a[href^="/notification_compose"]')) {
                const sendLink = document.createElement("a");
                sendLink.href = withAuth("/notification_compose");
                sendLink.textContent = "Send Notification";
                menu.insertBefore(sendLink, menu.firstChild);
            }
            if (role === "student" && !menu.querySelector('a[href^="/assignments"]')) {
                const assignmentLink = document.createElement("a");
                assignmentLink.href = withAuth("/assignments");
                assignmentLink.textContent = "Assignments";
                menu.insertBefore(assignmentLink, menu.firstChild);
            }
            if (role === "teacher" && !menu.querySelector('a[href^="/teacher_assignments"]')) {
                const assignmentLink = document.createElement("a");
                assignmentLink.href = withAuth("/teacher_assignments");
                assignmentLink.textContent = "Assignments";
                menu.insertBefore(assignmentLink, menu.firstChild);
            }
        }

        if (isValidAuth()) {
            fetch(withAuth("/notifications/unread_count"), { credentials: "same-origin" })
                .then(response => response.ok ? response.json() : { count: 0 })
                .then(data => {
                    const badge = bell.querySelector(".notification_badge");
                    const count = Number(data.count || 0);
                    if (!badge) return;
                    if (count > 0) {
                        badge.hidden = false;
                        badge.textContent = count > 99 ? "99+" : String(count);
                    }
                })
                .catch(() => {});
        }
    });

    // Wrap fetch immediately so inline page scripts also keep the tab identity.
    const originalFetch = window.fetch;
    window.fetch = function (input, init) {
        if (!isValidAuth()) return originalFetch(input, init);
        if (typeof input === "string") {
            input = withAuth(input);
        } else if (input instanceof Request) {
            input = new Request(withAuth(input.url), input);
        }
        return originalFetch(input, init);
    };
})();
