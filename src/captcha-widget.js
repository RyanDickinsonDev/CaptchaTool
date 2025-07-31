(async function () {
  const container = document.querySelector("[data-captcha]");
  if (!container) return;

  const shadowRoot = container.attachShadow({ mode: "open" });

  const res = await fetch("https://captchatool.com/generate", { method: "POST",  credentials: "include" });
  const { captchaId, question } = await res.json();

  shadowRoot.innerHTML = `
    <style>
      .captcha-box {
        display: flex;
        gap: 0.5rem;
        align-items: center;
        padding: 1rem;
        border: 1px solid #ccc;
        border-radius: 6px;
        background: #f9f9f9;
        font-family: Arial, sans-serif;
      }
      .captcha-box.success { border-color: #28a745; background: #e6f4ea; }
      .captcha-box.error { border-color: #dc3545; background: #f8d7da; }
    </style>
    <div class="captcha-box" id="captcha-container">
      <input type="checkbox" id="captcha-checkbox" />
      <label for="captcha-checkbox">${question}</label>
    </div>
  `;

  const form = container.closest("form");
  if (!form) return;

  const captchaIdInput = form.querySelector('input[name="captchaId"]');
  const validatedCaptchaInput = form.querySelector('input[name="validatedCaptcha"]');
  const botCheckInput = form.querySelector('input[name="botCheck"]');

  if (captchaIdInput) captchaIdInput.value = captchaId;
  if (validatedCaptchaInput) validatedCaptchaInput.value = "";

  const validateCaptcha = async () => {
    const checkbox = shadowRoot.querySelector("#captcha-checkbox");
    const captchaBox = shadowRoot.querySelector("#captcha-container");

    captchaBox.classList.remove("success", "error");

    const res = await fetch("https://captchatool.com/validate", {
      method: "POST",
       credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        captchaId,
        answer: "checkbox",
        botCheck: botCheckInput?.value || "",
      }),
    });

    const result = await res.json();

    if (result.valid) {
      captchaBox.classList.add("success");
      validatedCaptchaInput.value = captchaId;
      checkbox.disabled = true;
    } else {
      captchaBox.classList.add("error");
      validatedCaptchaInput.value = "";
    }
  };

  const checkbox = shadowRoot.querySelector("#captcha-checkbox");
  checkbox.addEventListener("change", () => {
    if (checkbox.disabled) return;
  
    if (checkbox.checked) {
      validateCaptcha();
    } else {
      const captchaBox = shadowRoot.querySelector("#captcha-container");
      captchaBox.classList.remove("success", "error");
      validatedCaptchaInput.value = "";
    }
  });
})();
