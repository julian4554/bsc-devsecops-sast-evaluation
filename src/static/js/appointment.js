// appointment.js
window.onload = () => {
    const token = localStorage.getItem("token");
    if (!token) {
        window.location.href = "/";
        return;
    }
};

async function createAppointment() {
    const token = localStorage.getItem("token");
    const patientId = parseInt(document.getElementById("patientId").value, 10);
    const rawDate = document.getElementById("date").value;
    const description = document.getElementById("description").value.trim();
    const msg = document.getElementById("message");

    msg.textContent = "";

    // Validation
    if (!patientId || patientId <= 0) {
        msg.textContent = "Invalid patient ID.";
        return;
    }

    if (!rawDate) {
        msg.textContent = "Please select a date.";
        return;
    }

    if (description.length === 0) {
        msg.textContent = "Description cannot be empty.";
        return;
    }

    // Convert datetime-local → Valid ISO8601
    const isoDate = rawDate + ":00";

    try {
        const res = await fetch("/appointments/create", {
            method: "POST",
            headers: {
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                patient_id: patientId,
                date: isoDate,
                description: description
            })
        });

        const data = await res.json();

        if (res.ok) {
            msg.textContent = "Appointment created successfully!";
            document.getElementById("description").value = "";
        } else {
            msg.textContent = data.error || "Creation failed.";
        }

    } catch (err) {
        msg.textContent = "Network error.";
    }
}

function goBack() {
    window.location.href = "/dashboard";
}
