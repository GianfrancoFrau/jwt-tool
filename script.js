window.addEventListener("load", () => {
  if (!window.jwt) {
    console.error("JWT module failed to load");
    return;
  }

  const { createJwt, parseJwt, verifyJwtSignature, errors: jwtErrors } = window.jwt;

  const tabButtons = Array.from(document.querySelectorAll(".tab-btn"));
  const tabPanels = Array.from(document.querySelectorAll(".tab-panel"));
  const validTabs = new Set(tabButtons.map((button) => button.dataset.tab));

  const applyTabState = (target) => {
    tabButtons.forEach((button) => {
      const isActive = button.dataset.tab === target;
      button.classList.toggle("active", isActive);
      button.setAttribute("aria-selected", String(isActive));
    });
    tabPanels.forEach((panel) => {
      const show = panel.dataset.panel === target;
      panel.classList.toggle("active", show);
      panel.toggleAttribute("hidden", !show);
    });
  };

  const setActiveTab = (target, { updateHash = true } = {}) => {
    if (!validTabs.has(target)) {
      return;
    }
    applyTabState(target);
    if (updateHash) {
      const newHash = `#${target}`;
      if (window.location.hash !== newHash) {
        history.replaceState(null, "", newHash);
      }
    }
  };

  const readHashTab = () => window.location.hash.slice(1).toLowerCase();

  const defaultTab = tabButtons[0]?.dataset.tab ?? "encode";
  const initialHashTab = readHashTab();
  const initialTab = validTabs.has(initialHashTab) ? initialHashTab : defaultTab;
  setActiveTab(initialTab, { updateHash: false });

  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      setActiveTab(button.dataset.tab);
    });
  });

  window.addEventListener("hashchange", () => {
    const hashTab = readHashTab();
    if (validTabs.has(hashTab)) {
      setActiveTab(hashTab, { updateHash: false });
    }
  });

  const encodeSecretInput = document.getElementById("encode-secret");
  const encodePayloadInput = document.getElementById("encode-payload");
  const encodeBtn = document.getElementById("encode-btn");
  const encodeResetBtn = document.getElementById("encode-reset-btn");
  const encodeResults = document.getElementById("encode-results");
  const encodeOutput = document.getElementById("encode-output");
  const encodeOutputBlock = document.getElementById("encode-output-block");
  const encodeError = document.getElementById("encode-error");

  const updateEncodeResetState = () => {
    const hasSecret = encodeSecretInput.value.trim().length > 0;
    const hasPayload = encodePayloadInput.value.trim().length > 0;
    encodeResetBtn.disabled = !(hasSecret || hasPayload);
  };

  const resetEncodeForm = () => {
    encodeSecretInput.value = "";
    encodePayloadInput.value = "";
    encodeError.hidden = true;
    encodeError.textContent = "";
    encodeOutput.textContent = "";
    encodeOutput.classList.remove("visible");
    encodeOutputBlock.hidden = true;
    encodeResults.hidden = true;
    updateEncodeResetState();
  };

  encodeSecretInput.addEventListener("input", updateEncodeResetState);
  encodePayloadInput.addEventListener("input", updateEncodeResetState);
  encodeResetBtn.addEventListener("click", resetEncodeForm);
  updateEncodeResetState();

  encodeBtn.addEventListener("click", async () => {
    encodeError.hidden = true;
    encodeError.textContent = "";
    encodeOutput.textContent = "";
    encodeOutput.classList.remove("visible");
    encodeOutputBlock.hidden = true;
    encodeResults.hidden = true;
    const secret = encodeSecretInput.value.trim();
    const payloadText = encodePayloadInput.value.trim();
    if (!secret) {
      encodeError.textContent = "Secret is required";
      encodeError.hidden = false;
      encodeResults.hidden = false;
      return;
    }
    try {
      const payload = JSON.parse(payloadText || "{}");
      const { token } = await createJwt({ payload, secret });
      encodeOutput.textContent = token;
      encodeOutput.classList.add("visible");
      encodeOutputBlock.hidden = false;
      encodeResults.hidden = false;
    } catch (err) {
      if (err instanceof SyntaxError) {
        encodeError.textContent = "Invalid payload: ensure it is valid JSON";
      } else {
        encodeError.textContent = "Error while generating the token";
        console.error("Token generation failed", err);
      }
      encodeError.hidden = false;
      encodeResults.hidden = false;
    }
  });

  const decodeTokenInput = document.getElementById("decode-token");
  const decodeSecretInput = document.getElementById("decode-secret");
  const decodeBtn = document.getElementById("decode-btn");
  const decodeResetBtn = document.getElementById("decode-reset-btn");
  const decodedHeader = document.getElementById("decoded-header");
  const decodedPayload = document.getElementById("decoded-payload");
  const decodedValid = document.getElementById("decoded-valid");
  const decodedHeaderBlock = document.getElementById("decoded-header-block");
  const decodedPayloadBlock = document.getElementById("decoded-payload-block");
  const decodedValidBlock = document.getElementById("decoded-valid-block");
  const decodeResults = document.getElementById("decode-results");
  const decodeError = document.getElementById("decode-error");

  const clearDecodeOutputs = () => {
    decodeResults.hidden = true;
    decodedHeaderBlock.hidden = true;
    decodedHeader.textContent = "";
    decodedHeader.classList.remove("visible");
    decodedPayloadBlock.hidden = true;
    decodedPayload.textContent = "";
    decodedPayload.classList.remove("visible");
    decodedValidBlock.hidden = true;
    decodedValid.textContent = "";
    decodedValid.classList.remove("visible");
  };

  const updateDecodeResetState = () => {
    const hasToken = decodeTokenInput.value.trim().length > 0;
    const hasSecret = decodeSecretInput.value.trim().length > 0;
    decodeResetBtn.disabled = !(hasToken || hasSecret);
  };

  const resetDecodeForm = () => {
    decodeTokenInput.value = "";
    decodeSecretInput.value = "";
    decodeError.hidden = true;
    decodeError.textContent = "";
    clearDecodeOutputs();
    updateDecodeResetState();
  };

  decodeTokenInput.addEventListener("input", updateDecodeResetState);
  decodeSecretInput.addEventListener("input", updateDecodeResetState);
  decodeResetBtn.addEventListener("click", resetDecodeForm);
  updateDecodeResetState();

  decodeBtn.addEventListener("click", async () => {
    decodeError.hidden = true;
    decodeError.textContent = "";
    clearDecodeOutputs();

    const token = decodeTokenInput.value.trim();
    if (!token) {
      decodeError.textContent = "Enter a JWT token";
      decodeError.hidden = false;
      return;
    }
    try {
      const parsed = parseJwt(token);
      decodedHeader.textContent = JSON.stringify(parsed.header, null, 2);
      decodedHeader.classList.add("visible");
      decodedHeaderBlock.hidden = false;
      decodedPayload.textContent = JSON.stringify(parsed.payload, null, 2);
      decodedPayload.classList.add("visible");
      decodedPayloadBlock.hidden = false;
      decodeResults.hidden = false;
      const secret = decodeSecretInput.value.trim();
      if (secret) {
        const isValid = await verifyJwtSignature({
          secret,
          headerPart: parsed.headerPart,
          payloadPart: parsed.payloadPart,
          signature: parsed.signature,
        });
        decodedValid.textContent = isValid ? "Yes" : "No";
        decodedValid.classList.add("visible");
        decodedValidBlock.hidden = false;
      } else {
        decodedValid.textContent = "Secret not provided";
        decodedValid.classList.add("visible");
        decodedValidBlock.hidden = false;
      }
    } catch (err) {
      if (err instanceof SyntaxError) {
        decodeError.textContent = "Unable to decode header or payload";
      } else if (err?.name === "JwtError") {
        if (err.code === jwtErrors.InvalidFormat) {
          decodeError.textContent = "Invalid token format";
        } else {
          decodeError.textContent = err.message;
        }
      } else {
        decodeError.textContent = "Unable to decode header or payload";
        console.error("Token decoding failed", err);
      }
      decodeError.hidden = false;
      return;
    }
  });

  const copyButtons = Array.from(document.querySelectorAll(".copy-btn"));

  const writeToClipboard = async (text) => {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);
  };

  copyButtons.forEach((button) => {
    const originalLabel = button.textContent;
    button.addEventListener("click", async () => {
      const targetId = button.dataset.copyTarget;
      const target = document.getElementById(targetId);
      if (!target) {
        return;
      }
      const text = target.textContent.trim();
      if (!text) {
        return;
      }
      button.disabled = true;
      try {
        await writeToClipboard(text);
        button.textContent = "Copied!";
      } catch (err) {
        console.error("Copy to clipboard failed", err);
        button.textContent = "Error";
      }
      setTimeout(() => {
        button.textContent = originalLabel;
        button.disabled = false;
      }, 1200);
    });
  });
});
