// fhir.js

window.onload = async () => {
    const token = localStorage.getItem("token");
    const output = document.getElementById("fhirOutput");
    const msg = document.getElementById("message");

    if (!token) {
        window.location.href = "/";
        return;
    }

    try {
        const res = await fetch(`/fhir/Patient/${PATIENT_ID}`, {
            headers: {
                "Authorization": "Bearer " + token
            }
        });

        // 401 → Session expired → logout + redirect
        if (res.status === 401) {
            localStorage.clear();
            window.location.href = "/";
            return;
        }

        const data = await res.json();

        // 403 → Keine Berechtigung → anzeigen, aber nicht abstürzen
        if (res.status === 403) {
            msg.textContent = "You are not allowed to view this FHIR resource.";
            output.textContent = "";
            return;
        }

        // 404 → Patient existiert nicht
        if (res.status === 404) {
            msg.textContent = "Patient not found.";
            output.textContent = "";
            return;
        }

        if (!res.ok) {
            msg.textContent = data.error || "Failed to load FHIR resource.";
            output.textContent = "";
            return;
        }

        // SAFE: textContent (kein innerHTML)
        output.textContent = JSON.stringify(data, null, 4);

    } catch (err) {
        msg.textContent = "Network error.";
        output.textContent = "";
    }
};

function goBack() {
    window.location.href = `/patient/${PATIENT_ID}`;
}
