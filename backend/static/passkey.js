(() => {
  "use strict";
  /* Passkey ceremonies in the browser, shared by the console (/ui/), /invite, /join and /reset-password.

     The server sends WebAuthn options as JSON with binary fields in base64url
     (POST /auth/passkey/.../begin) and takes the credential back in the same encoding
     (POST /auth/passkey/.../finish). This file converts between the two and calls
     navigator.credentials. It makes no requests itself and keeps nothing.

       MorrowPasskey.supported()            -> boolean
       MorrowPasskey.conditionalAvailable() -> Promise<boolean>  (autofill / conditional UI)
       MorrowPasskey.create(options)        -> Promise<credential JSON>
       MorrowPasskey.get(options, { conditional, signal }) -> Promise<credential JSON>
       MorrowPasskey.message(error)         -> a sentence for the person, or "" when they cancelled */

  const toBytes = text => {
    const b64 = String(text || "").replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64 + "===".slice((b64.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  };
  const toText = buffer => {
    if (!buffer) return null;
    const bytes = new Uint8Array(buffer);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const descriptors = list => (list || []).map(d => ({ ...d, id: toBytes(d.id) }));

  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext);
  }
  async function conditionalAvailable() {
    try {
      return supported() && typeof PublicKeyCredential.isConditionalMediationAvailable === "function"
        && await PublicKeyCredential.isConditionalMediationAvailable();
    } catch { return false; }
  }

  async function create(options) {
    const publicKey = {
      ...options,
      challenge: toBytes(options.challenge),
      user: { ...options.user, id: toBytes(options.user.id) },
      excludeCredentials: descriptors(options.excludeCredentials)
    };
    const cred = await navigator.credentials.create({ publicKey });
    const r = cred.response;
    return {
      id: cred.id, rawId: toText(cred.rawId), type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: {
        clientDataJSON: toText(r.clientDataJSON),
        attestationObject: toText(r.attestationObject),
        transports: typeof r.getTransports === "function" ? r.getTransports() : []
      }
    };
  }

  async function get(options, { conditional = false, signal } = {}) {
    const publicKey = { ...options, challenge: toBytes(options.challenge), allowCredentials: descriptors(options.allowCredentials) };
    const request = { publicKey };
    if (conditional) request.mediation = "conditional";
    if (signal) request.signal = signal;
    const cred = await navigator.credentials.get(request);
    const r = cred.response;
    return {
      id: cred.id, rawId: toText(cred.rawId), type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: {
        clientDataJSON: toText(r.clientDataJSON),
        authenticatorData: toText(r.authenticatorData),
        signature: toText(r.signature),
        userHandle: toText(r.userHandle)
      }
    };
  }

  function message(error) {
    const name = error && error.name;
    if (name === "AbortError") return "";
    if (name === "NotAllowedError") return "";   // cancelled, timed out, or no passkey chosen
    if (name === "InvalidStateError") return "This device already has a passkey for this account.";
    if (name === "SecurityError") return "Passkeys only work on this site's own address, over HTTPS.";
    if (name === "NotSupportedError") return "This browser or device can't create a passkey. Try another one, or a phone.";
    return "The passkey didn't work. Try again.";
  }

  window.MorrowPasskey = Object.freeze({ supported, conditionalAvailable, create, get, message });
})();
