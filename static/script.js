
import {
    auth,
    createUserWithEmailAndPassword,
    signInWithEmailAndPassword,
    signOut,
    onAuthStateChanged
} from "./firebase.js";

const authSection = document.getElementById("authSection");
const appSection = document.getElementById("appSection");
const authForm = document.getElementById("authForm");
const authTitle = document.getElementById("authTitle");
const authSubtitle = document.getElementById("authSubtitle");
const authButton = document.getElementById("authButton");
const authMessage = document.getElementById("authMessage");
const switchButton = document.getElementById("switchButton");
const switchText = document.getElementById("switchText");

let isRegisterMode = false;
let currentUser = null;

function showMessage(message, isError = true) {
    authMessage.textContent = message;
    authMessage.style.color = isError ? "#ff9c9c" : "#45d6c5";
}

function setAuthMode(registerMode) {
    isRegisterMode = registerMode;

    authTitle.textContent = registerMode ? "Create your account" : "Welcome back";
    authSubtitle.textContent = registerMode
        ? "Register to start protecting yourself from phishing links."
        : "Sign in to continue to your security dashboard.";

    authButton.textContent = registerMode ? "Create Account" : "Sign In";
    switchText.textContent = registerMode
        ? "Already have an account?"
        : "Don't have an account?";

    switchButton.textContent = registerMode ? "Sign in" : "Create account";
    showMessage("");
}

switchButton.addEventListener("click", () => {
    setAuthMode(!isRegisterMode);
});

authForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;

    authButton.disabled = true;
    authButton.textContent = "Please wait...";
    showMessage("");

    try {
        if (isRegisterMode) {
            await createUserWithEmailAndPassword(auth, email, password);
        } else {
            await signInWithEmailAndPassword(auth, email, password);
        }
    } catch (error) {
        showMessage(error.message);
    } finally {
        authButton.disabled = false;
        authButton.textContent = isRegisterMode ? "Create Account" : "Sign In";
    }
});

async function getToken() {
    if (!currentUser) {
        throw new Error("Please sign in first.");
    }

    return await currentUser.getIdToken();
}

async function apiRequest(endpoint, options = {}) {
    const token = await getToken();

    const response = await fetch(endpoint, {
        ...options,
        headers: {
            "Content-Type": "application/json",
            ...(options.headers || {}),
            "Authorization": `Bearer ${token}`
        }
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(data.detail || `Request failed: ${response.status}`);
    }

    return data;
}

function showPage(pageName) {
    const pages = ["dashboard", "analyze", "history", "insights", "howto"];

    pages.forEach((name) => {
        document.getElementById(`${name}Page`).classList.toggle(
            "hidden",
            name !== pageName
        );
    });

    document.querySelectorAll(".nav-button").forEach((button) => {
        button.classList.toggle("active", button.dataset.page === pageName);
    });

    const titles = {
        dashboard: "Dashboard",
        analyze: "Analyze URL",
        history: "Scan History",
        insights: "Model Insights",
        howto: "How to Use"
    };

    document.getElementById("pageTitle").textContent = titles[pageName];

    if (pageName === "dashboard") loadDashboard();
    if (pageName === "history") loadHistory();
}

document.querySelectorAll(".nav-button").forEach((button) => {
    button.addEventListener("click", () => showPage(button.dataset.page));
});

document.querySelectorAll("[data-go]").forEach((button) => {
    button.addEventListener("click", () => showPage(button.dataset.go));
});

document.getElementById("logoutButton").addEventListener("click", async () => {
    await signOut(auth);
});

function displayScanItems(container, data) {
    const items = Array.isArray(data)
        ? data
        : (data.scans || data.history || data.recent_scans || []);

    if (!items.length) {
        container.textContent = "No scans found yet. Analyze your first URL to see activity here.";
        return;
    }

    container.innerHTML = items.map((scan) => `
        <div class="scan-item">
            <p><strong>${escapeHtml(scan.prediction ?? "Unknown")}</strong></p>
            <p>${escapeHtml(scan.url ?? "")}</p>
            <p>Risk score: ${escapeHtml(scan.risk_score ?? "—")}%</p>
            <p class="note">${escapeHtml(scan.scanned_at ?? "")}</p>
        </div>
    `).join("");
}

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (character) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
    })[character]);
}

async function loadDashboard() {
    const recent = document.getElementById("recentScans");

    try {
        const data = await apiRequest("/api/dashboard");

        document.getElementById("totalScans").textContent =
            data.total_scans ?? data.total ?? 0;

        document.getElementById("phishingScans").textContent =
            data.phishing_scans ?? data.phishing ?? 0;

        document.getElementById("legitimateScans").textContent =
            data.legitimate_scans ?? data.legitimate ?? 0;

        document.getElementById("suspiciousScans").textContent =
            data.suspicious_scans ?? data.suspicious ?? 0;

        displayScanItems(recent, data);
    } catch (error) {
        recent.textContent = error.message;
    }
}

document.getElementById("analyzeForm").addEventListener("submit", async (event) => {
    event.preventDefault();

    const urlInput = document.getElementById("urlInput");
    const result = document.getElementById("analysisResult");
    const button = document.getElementById("analyzeButton");

    const url = urlInput.value.trim();

    if (!url) return;

    button.disabled = true;
    button.textContent = "Analyzing...";
    result.classList.remove("hidden");
    result.textContent = "Checking URL. Please wait...";

    try {
        const data = await apiRequest("/api/analyze", {
            method: "POST",
            body: JSON.stringify({ url })
        });

        const reasons = Array.isArray(data.reasons)
            ? data.reasons
            : [];

        result.innerHTML = `
            <h3>Analysis Result</h3>
            <p><strong>Prediction:</strong> ${escapeHtml(data.prediction ?? "Not provided")}</p>
            <p><strong>Risk Score:</strong> ${escapeHtml(data.risk_score ?? "—")}%</p>
            <p><strong>URL:</strong> ${escapeHtml(data.url ?? url)}</p>
            <p><strong>Detection Reasons:</strong></p>
            ${
                reasons.length
                ? `<ul>${reasons.map(reason => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>`
                : "<p>No explanation details were returned by the server.</p>"
            }
        `;

        loadDashboard();
    } catch (error) {
        result.textContent = error.message;
    } finally {
        button.disabled = false;
        button.textContent = "Analyze URL";
    }
});

async function loadHistory() {
    const historyList = document.getElementById("historyList");
    historyList.textContent = "Loading history...";

    try {
        const data = await apiRequest("/api/history");
        displayScanItems(historyList, data);
    } catch (error) {
        historyList.textContent = error.message;
    }
}

document.getElementById("refreshHistory").addEventListener("click", loadHistory);

onAuthStateChanged(auth, async (user) => {
    currentUser = user;

    if (user) {
        authSection.classList.add("hidden");
        appSection.classList.remove("hidden");
        document.getElementById("userEmail").textContent = user.email || "Signed in";

        try {
            await apiRequest("/api/me");
            showPage("dashboard");
        } catch (error) {
            await signOut(auth);
            showMessage(error.message);
        }
    } else {
        appSection.classList.add("hidden");
        authSection.classList.remove("hidden");
    }
});
