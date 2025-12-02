// patient.js

window.onload = async () => {
    const token = localStorage.getItem("token");
    const msg = document.getElementById("message");

    if (!token) {
        window.location.href = "/";
        return;
    }

    try {
        const res = await fetch(`/patient/${PATIENT_ID}`, {
            headers: { "Authorization": "Bearer " + token }
        });

        // 401 → Session abgelaufen
        if (res.status === 401) {
            localStorage.clear();
            window.location.href = "/";
            return;
        }

        const data = await res.json();

        // 403 → Rolle unzureichend (sollte bei GET nicht passieren)
        if (res.status === 403) {
            msg.textContent = "You are not allowed to view this patient.";
            return;
        }

        if (!res.ok) {
            msg.textContent = data.error || "Failed to load patient.";
            return;
        }

        // SAFE (kein innerHTML)
        document.getElementById("name").textContent = `${data.first_name} ${data.last_name}`;
        document.getElementById("diagnosis").textContent = data.diagnosis;
        document.getElementById("birthdate").textContent = data.birthdate;

        // Für doctor sichtbar: MRN
        if (data.insurance_number) {
            // Legacy fallback
            document.getElementById("insurance").textContent = data.insurance_number;
        } else if (data.mrn) {
            document.getElementById("insurance").textContent = data.mrn;
        } else {
            document.getElementById("insurance").textContent = "Not available";
        }

        // ROLE HANDLING: Diagnose-Update nur für doctors erlauben
        const role = localStorage.getItem("role"); // wir speichern das gleich im Login mit
        if (role !== "doctor") {
            document.getElementById("newDiagnosis").style.display = "none";
            document.querySelector("button[onclick='updateDiagnosis()']").style.display = "none";
        }

    } catch (err) {
        msg.textContent = "Network error.";
    }
};


async function updateDiagnosis() {
    const token = localStorage.getItem("token");
    const msg = document.getElementById("message");
    const diagnosis = document.getElementById("newDiagnosis").value.trim();

    msg.textContent = "";

    if (diagnosis.length === 0) {
        msg.textContent = "Diagnosis cannot be empty.";
        return;
    }

    try {
        const res = await fetch("/patient/update", {
            method: "POST",
            headers: {
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                id: PATIENT_ID,
                diagnosis: diagnosis
            })
        });

        // 401 → Session expired
        if (res.status === 401) {
            localStorage.clear();
            window.location.href = "/";
            return;
        }

        const data = await res.json();

        if (!res.ok) {
            msg.textContent = data.error || "Update failed.";
            return;
        }

        // Erfolgreich
        document.getElementById("diagnosis").textContent = diagnosis;
        document.getElementById("newDiagnosis").value = "";
        msg.textContent = "Updated successfully!";

    } catch (err) {
        msg.textContent = "Network error.";
    }
}


function goBack() {
    window.location.href = "/dashboard";
}

function openFHIR() {
    window.location.href = `/fhir_view/${PATIENT_ID}`;
}
