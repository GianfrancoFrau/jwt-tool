(() => {
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  // Build a recognizable error object that the UI can inspect.
  const createJwtError = (code, message) => {
    const error = new Error(message);
    error.name = "JwtError";
    error.code = code;
    return error;
  };

  // Encode data to Base64 URL-safe format.
  const toBase64Url = (input) => {
    const bytes = typeof input === "string" ? textEncoder.encode(input) : new Uint8Array(input);
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  // Decode Base64 URL-safe data back to text.
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

  // Convert Base64 URL-safe data into raw bytes.
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

  // Prepare an HMAC key from the provided secret.
  const importHmacKey = async (secret) => {
    return crypto.subtle.importKey(
      "raw",
      textEncoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
  };

  // Compute an HS256 signature for the given signing input.
  const sign = async (secret, data) => {
    const key = await importHmacKey(secret);
    const signature = await crypto.subtle.sign("HMAC", key, textEncoder.encode(data));
    return toBase64Url(signature);
  };

  // Verify an HS256 signature against the provided data.
  const verify = async (secret, data, signatureB64) => {
    const key = await importHmacKey(secret);
    const signatureBytes = base64UrlToUint8Array(signatureB64);
    return crypto.subtle.verify("HMAC", key, signatureBytes, textEncoder.encode(data));
  };

  // Split and validate the three JWT segments.
  const splitToken = (token) => {
    if (typeof token !== "string" || !token.trim()) {
      throw createJwtError("INVALID_TOKEN", "Token must be a non-empty string");
    }
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw createJwtError("INVALID_FORMAT", "Invalid token format");
    }
    const [headerPart, payloadPart, signaturePart] = parts;
    return { headerPart, payloadPart, signaturePart };
  };

  // Create a signed JWT from header, payload, and secret.
  const createJwt = async ({ header = { alg: "HS256", typ: "JWT" }, payload, secret }) => {
    if (typeof secret !== "string" || !secret.trim()) {
      throw createJwtError("MISSING_SECRET", "Secret is required");
    }
    if (payload === undefined) {
      throw createJwtError("MISSING_PAYLOAD", "Payload is required");
    }
    const encodedHeader = toBase64Url(JSON.stringify(header));
    const encodedPayload = toBase64Url(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signature = await sign(secret, signingInput);
    return {
      token: `${signingInput}.${signature}`,
      headerPart: encodedHeader,
      payloadPart: encodedPayload,
      signature,
    };
  };

  // Decode a JWT into its parsed components.
  const parseJwt = (token) => {
    const { headerPart, payloadPart, signaturePart } = splitToken(token);
    let header;
    let payload;
    try {
      header = JSON.parse(fromBase64Url(headerPart));
    } catch (error) {
      throw createJwtError("DECODE_HEADER", "Unable to decode header");
    }
    try {
      payload = JSON.parse(fromBase64Url(payloadPart));
    } catch (error) {
      throw createJwtError("DECODE_PAYLOAD", "Unable to decode payload");
    }
    return {
      header,
      payload,
      headerPart,
      payloadPart,
      signature: signaturePart,
    };
  };

  // Verify a JWT signature using the supplied secret.
  const verifyJwtSignature = async ({ secret, headerPart, payloadPart, signature }) => {
    if (typeof secret !== "string" || !secret.trim()) {
      throw createJwtError("MISSING_SECRET", "Secret is required");
    }
    try {
      const signingInput = `${headerPart}.${payloadPart}`;
      return await verify(secret, signingInput, signature);
    } catch (error) {
      console.error("Signature verification failed", error);
      return false;
    }
  };

  const errors = {
    InvalidToken: "INVALID_TOKEN",
    InvalidFormat: "INVALID_FORMAT",
    MissingSecret: "MISSING_SECRET",
    MissingPayload: "MISSING_PAYLOAD",
    DecodeHeader: "DECODE_HEADER",
    DecodePayload: "DECODE_PAYLOAD",
  };

  window.jwt = {
    createJwt,
    parseJwt,
    verifyJwtSignature,
    errors,
  };
})();
