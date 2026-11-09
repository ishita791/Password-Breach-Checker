
// =====================================
// PASSWORDGUARD - PASSWORD BREACH CHECKER
// Official Have I Been Pwned API
// =====================================


// Get HTML elements
const passwordInput = document.getElementById("password");
const checkBtn = document.getElementById("checkBtn");
const togglePassword = document.getElementById("togglePassword");
const loading = document.getElementById("loading");
const result = document.getElementById("result");


// =====================================
// 1. SHOW / HIDE PASSWORD
// =====================================

togglePassword.addEventListener("click", () => {

    if (passwordInput.type === "password") {

        passwordInput.type = "text";
        togglePassword.textContent = "Hide";
        togglePassword.setAttribute("aria-label", "Hide password");

    } else {

        passwordInput.type = "password";
        togglePassword.textContent = "Show";
        togglePassword.setAttribute("aria-label", "Show password");

    }

});


// =====================================
// 2. GENERATE SHA-1 HASH
// =====================================

async function generateSHA1(password) {

    // Convert password into bytes
    const encoder = new TextEncoder();

    const data = encoder.encode(password);

    // Generate SHA-1 hash using Web Crypto API
    const hashBuffer = await crypto.subtle.digest("SHA-1", data);

    // Convert hash bytes into hexadecimal
    const hashArray = Array.from(new Uint8Array(hashBuffer));

    const hashHex = hashArray
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("")
        .toUpperCase();

    return hashHex;

}


// =====================================
// 3. CHECK PASSWORD USING HIBP API
// =====================================

async function checkPassword() {

    const password = passwordInput.value;

    // Validate input
    if (password.length === 0) {

        showError("Please enter a password first.");
        passwordInput.focus();

        return;

    }

    // Check browser support
    if (!window.isSecureContext || !crypto.subtle) {

        showError(
            "Secure browser context is required. Run the website using VS Code Live Server or HTTPS."
        );

        return;

    }

    // Show loading
    loading.classList.remove("hidden");
    result.classList.add("hidden");

    checkBtn.disabled = true;
    checkBtn.querySelector("span:first-child").textContent = "Checking...";

    try {

        // Step 1: Generate SHA-1 hash
        const hash = await generateSHA1(password);

        // Step 2: Split hash into prefix and suffix
        const prefix = hash.substring(0, 5);
        const suffix = hash.substring(5);

        // Step 3: Send only first five characters to HIBP
        const apiURL =
            `https://api.pwnedpasswords.com/range/${prefix}`;

        const response = await fetch(apiURL, {

            method: "GET",

            headers: {
                "Add-Padding": "true",
                "Accept": "text/plain"
            },

            cache: "no-store"

        });

        // Step 4: Check API response
        if (!response.ok) {

            throw new Error(
                `HIBP API request failed. HTTP status: ${response.status}`
            );

        }

        // Step 5: Get hash suffix list
        const responseText = await response.text();

        // Step 6: Find matching hash suffix
        const lines = responseText.split(/\r?\n/);

        let exposureCount = 0;

        for (const line of lines) {

            if (!line.includes(":")) {
                continue;
            }

            const [returnedSuffix, countText] = line.split(":");

            if (returnedSuffix.trim().toUpperCase() === suffix) {

                const count = Number(countText.trim());

                if (!Number.isSafeInteger(count) || count < 0) {
                    throw new Error("Invalid occurrence count received from API.");
                }

                exposureCount = count;

                break;

            }

        }

        // Step 7: Display result
        if (exposureCount > 0) {

            showExposedResult(exposureCount);

        } else {

            showSafeResult();

        }

    } catch (error) {

        // Handle errors without logging the password
        showError(
            "Unable to check your password right now. Please check your internet connection and try again."
        );

    } finally {

        // Hide loading and enable button
        loading.classList.add("hidden");

        checkBtn.disabled = false;
        checkBtn.querySelector("span:first-child").textContent =
            "Check Password";

    }

}


// =====================================
// 4. SHOW EXPOSED RESULT
// =====================================

function showExposedResult(count) {

    result.className = "result exposed";

    result.innerHTML = `

        <div class="result-icon">⚠️</div>

        <h3>Password Exposed!</h3>

        <p>
            This password was found in the
            Have I Been Pwned Pwned Passwords database.
        </p>

        <div class="exposure-count">
            ${count.toLocaleString("en-US")}
        </div>

        <p>
            Times this password appeared in the
            known breach corpus.
        </p>

        <div class="result-advice">

            <p>
                <strong>Security Recommendation:</strong>
            </p>

            <p>
                Stop using this password. Change it immediately
                on every account where you have used it.
                Choose a unique password for each account.
            </p>

        </div>

    `;

}


// =====================================
// 5. SHOW SAFE RESULT
// =====================================

function showSafeResult() {

    result.className = "result safe";

    result.innerHTML = `

        <div class="result-icon">✅</div>

        <h3>No Exposure Found!</h3>

        <p>
            This password was not found in the
            current Pwned Passwords database.
        </p>

        <div class="result-advice">

            <p>
                <strong>Good news!</strong>
            </p>

            <p>
                However, this does not guarantee that
                your password is completely secure.
                Always use a strong and unique password.
            </p>

        </div>

    `;

}


// =====================================
// 6. SHOW ERROR MESSAGE
// =====================================

function showError(message) {

    result.className = "result error";

    result.innerHTML = `

        <div class="result-icon">⚠️</div>

        <h3>Something Went Wrong</h3>

        <p>${message}</p>

    `;

    loading.classList.add("hidden");
    result.classList.remove("hidden");

}


// =====================================
// 7. BUTTON CLICK EVENT
// =====================================

checkBtn.addEventListener("click", checkPassword);


// Allow Enter key to check password
passwordInput.addEventListener("keydown", (event) => {

    if (event.key === "Enter" && !checkBtn.disabled) {

        checkPassword();

    }

});
