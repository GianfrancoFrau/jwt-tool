window.addEventListener("load", () => {
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

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

  const toBase64Url = (input) => {
    const bytes = typeof input === "string" ? textEncoder.encode(input) : new Uint8Array(input);
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  const fromBase64Url = (input) => {
    const padded = input.replace(/-/g, "+").replace(/_/g, "/");
    const padLength = (4 - (padded.length % 4)) % 4;
    const base64 = padded + "=".repeat(padLength);
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return textDecoder.decode(bytes);
  };

  const base64UrlToUint8Array = (input) => {
    const padded = input.replace(/-/g, "+").replace(/_/g, "/");
    const padLength = (4 - (padded.length % 4)) % 4;
    const base64 = padded + "=".repeat(padLength);
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  };

  const importHmacKey = async (secret) => {
    return crypto.subtle.importKey(
      "raw",
      textEncoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
  };

  const sign = async (secret, data) => {
    const key = await importHmacKey(secret);
    const signature = await crypto.subtle.sign("HMAC", key, textEncoder.encode(data));
    return toBase64Url(signature);
  };

  const verify = async (secret, data, signatureB64) => {
    try {
      const key = await importHmacKey(secret);
      const signatureBytes = base64UrlToUint8Array(signatureB64);
      return crypto.subtle.verify("HMAC", key, signatureBytes, textEncoder.encode(data));
    } catch (err) {
      console.error("Verifica firma fallita", err);
      return false;
    }
  };

  const encodeSecretInput = document.getElementById("encode-secret");
  const encodePayloadInput = document.getElementById("encode-payload");
  const encodeBtn = document.getElementById("encode-btn");
  const encodeOutput = document.getElementById("encode-output");
  const encodeOutputBlock = document.getElementById("encode-output-block");
  const encodeError = document.getElementById("encode-error");

  encodeBtn.addEventListener("click", async () => {
    encodeError.hidden = true;
    encodeError.textContent = "";
    encodeOutput.textContent = "";
    encodeOutput.classList.remove("visible");
    encodeOutputBlock.hidden = true;
    const secret = encodeSecretInput.value.trim();
    const payloadText = encodePayloadInput.value.trim();
    if (!secret) {
      encodeError.textContent = "La secret è obbligatoria";
      encodeError.hidden = false;
      return;
    }
    try {
      const payload = JSON.parse(payloadText || "{}");
      const header = { alg: "HS256", typ: "JWT" };
      const encodedHeader = toBase64Url(JSON.stringify(header));
      const encodedPayload = toBase64Url(JSON.stringify(payload));
      const signingInput = `${encodedHeader}.${encodedPayload}`;
      const signature = await sign(secret, signingInput);
      encodeOutput.textContent = `${signingInput}.${signature}`;
      encodeOutput.classList.add("visible");
      encodeOutputBlock.hidden = false;
    } catch (err) {
      encodeError.textContent = "Payload non valido: assicurati che sia JSON";
      encodeError.hidden = false;
    }
  });

  const decodeTokenInput = document.getElementById("decode-token");
  const decodeSecretInput = document.getElementById("decode-secret");
  const decodeBtn = document.getElementById("decode-btn");
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

  decodeBtn.addEventListener("click", async () => {
    decodeError.hidden = true;
    decodeError.textContent = "";
    clearDecodeOutputs();

    const token = decodeTokenInput.value.trim();
    if (!token) {
      decodeError.textContent = "Inserisci un token JWT";
      decodeError.hidden = false;
      return;
    }
    const parts = token.split(".");
    if (parts.length !== 3) {
      decodeError.textContent = "Formato token non valido";
      decodeError.hidden = false;
      return;
    }
    const [headerPart, payloadPart, signaturePart] = parts;
    try {
      decodedHeader.textContent = JSON.stringify(JSON.parse(fromBase64Url(headerPart)), null, 2);
      decodedHeader.classList.add("visible");
      decodedHeaderBlock.hidden = false;
      decodedPayload.textContent = JSON.stringify(JSON.parse(fromBase64Url(payloadPart)), null, 2);
      decodedPayload.classList.add("visible");
      decodedPayloadBlock.hidden = false;
      decodeResults.hidden = false;
    } catch (err) {
      decodeError.textContent = "Impossibile decodificare header o payload";
      decodeError.hidden = false;
      return;
    }
    const secret = decodeSecretInput.value.trim();
    if (secret) {
      const signingInput = `${headerPart}.${payloadPart}`;
      const isValid = await verify(secret, signingInput, signaturePart);
      decodedValid.textContent = isValid ? "Sì" : "No";
      decodedValid.classList.add("visible");
      decodedValidBlock.hidden = false;
    } else {
      decodedValid.textContent = "Secret non fornita";
      decodedValid.classList.add("visible");
      decodedValidBlock.hidden = false;
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
        button.textContent = "Copiato!";
      } catch (err) {
        console.error("Copia negli appunti fallita", err);
        button.textContent = "Errore";
      }
      setTimeout(() => {
        button.textContent = originalLabel;
        button.disabled = false;
      }, 1200);
    });
  });
});
