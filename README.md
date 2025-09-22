# 🛠️ JWT Tool

**This experiment was built using OpenAI Codex (with the gpt-5-codex model) as a test to assess its capabilities. Codex generated most of the code, with prompts aimed at implementing specific user-interface features (tab navigation, CSS tweaks, etc.) and code structure.**

## About

JWT Tool is a lightweight, client-side app for encoding, decoding, and verifying JSON Web Tokens (JWTs). It runs entirely in the browser and relies on the Web Crypto API to generate and validate `HS256` signatures without sending data to any backend service.

## Features
- Encode JSON payloads into signed JWTs using an `HS256` secret.
- Decode existing tokens and inspect their header and payload segments.
- Optionally verify the signature of a decoded token against a shared secret.
- Copy-friendly outputs for tokens, headers, payloads, and signature validation results.
- Accessible tabbed interface that remembers the active tab via the URL hash.

## Getting Started
1. Clone or download this repository.
2. Serve the project directory with a static file server (for example `python3 -m http.server`) or open `index.html` directly in your browser.
3. Navigate to the served URL (defaults to `http://localhost:8000` when using Python's HTTP server) or the opened file.

Because everything runs in the browser, no build step or external dependencies are required.

## Usage
### Encode a token
1. Open the **Encode** tab.
2. Enter the shared secret you want to sign with.
3. Provide a JSON payload. The default prompt shows a sample object; you can paste or type any valid JSON.
4. Click **Generate token** to produce a signed JWT. Use the **Copy** button to copy the token.

### Decode a token
1. Switch to the **Decode** tab.
2. Paste a JWT into the token field.
3. (Optional) Provide the secret to verify the signature.
4. Click **Decode** to inspect the header and payload. If a secret is supplied, the app reports whether the signature validates.

## Implementation Notes
- Cryptographic operations use the browser's native `crypto.subtle` APIs, so signature generation/verification stays on-device.
- Secrets are never persisted; resetting the form clears all in-memory values.
- Only `HS256` (HMAC SHA-256) signing is implemented. Other JWT algorithms are out of scope for this tool.

## Development
The project consists of static assets (`index.html`, `styles.css`, `jwt.js`, `script.js`). To make changes:

```bash
# Serve the files with live reload (example using npm's http-server)
npx http-server
```

Edit the files and refresh the browser to see updates. No bundler or transpiler is required.
