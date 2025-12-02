// dashboard.js

// Check if token exists, otherwise redirect
window.onload = () => {
    const token = localStorage.getItem("token");
    if (!token) {
        window.location.href = "/";
    }
};

async function searchPatients() {
    const query = document.getElementById("searchInput").value.trim();
    const msg = document.getElementById("message");
    const resultsList = document.getElementById("results");
    const token = localStorage.getItem("token");

    resultsList.innerHTML = "";
    msg.textContent = "";

    if (query.length === 0) {
        msg.textContent = "Please enter a search term.";
        return;
    }

    try {
        const res = await fetch(`/search?q=${encodeURIComponent(query)}`, {
            headers: {
                "Authorization": "Bearer " + token
            }
        });

        // Handle unauthorized → logout
        if (res.status === 401) {
            localStorage.clear();
            window.location.href = "/";
            return;
        }

        const data = await res.json();

        if (!res.ok) {
            msg.textContent = data.error || "Search failed.";
            return;
        }

        if (data.results.length === 0) {
            msg.textContent = "No results found.";
            return;
        }

        data.results.forEach(p => {
            const li = document.createElement("li");
            li.textContent = `${p.first_name} ${p.last_name}`;
            li.addEventListener("click", () => {
                window.location.href = `/patient/${p.id}`;
            });
            resultsList.appendChild(li);
        });

    } catch (err) {
        msg.textContent = "Network error.";
    }
}

function logout() {
    localStorage.clear();
    window.location.href = "/";
}

function goToAppointment() {
    window.location.href = "/appointment";
}
