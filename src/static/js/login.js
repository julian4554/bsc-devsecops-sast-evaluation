// login.js

document.getElementById("loginForm").onsubmit = async (e) => {
    e.preventDefault();

    // alte Session löschen
    localStorage.removeItem("token");

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value.trim();
    const msg = document.getElementById("message");

    msg.textContent = "";

    // Eingabeprüfung
    if (username.length === 0 || password.length === 0) {
        msg.textContent = "Please enter both username and password.";
        return;
    }

    try {
        const res = await fetch("/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username, password })
        });

        const data = await res.json();

        // 401 → Login falsch / Session ungültig
        if (res.status === 401) {
            msg.textContent = "Invalid username or password.";
            return;
        }

        if (!res.ok || !data.token) {
            msg.textContent = data.error || "Login failed.";
            return;
        }

        // Token speichern
        localStorage.setItem("token", data.token);

        // Weiterleitung zum Dashboard
        window.location.href = "/dashboard";

    } catch (err) {
        msg.textContent = "Network error.";
    }
};
