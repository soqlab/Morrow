(() => {
  "use strict";
  /* Sign in with SOQLAB, in the browser: shared by the console (/ui/), /signup and /reset-password.

     start() asks this server for a round trip (POST /auth/soqlab/start) and goes to id.soqlab.com. The
     server answers with a random `flow` secret that binds the round trip to this tab: it is kept in
     sessionStorage (never a cookie) and sent back with the code. id.soqlab.com returns to
     /auth/soqlab/callback, which sends the browser back to the page that started, with
     ?soqlab_code=&soqlab_state=&soqlab_iss= (or soqlab_error=). pending() reads and strips those;
     finish() posts them with the flow secret (POST /auth/soqlab/callback).

       MorrowSoqlab.start(purpose, body, { token, keep }) -> Promise<{ ok, status, detail }> (navigates away on success)
       MorrowSoqlab.pending()                             -> { code, state, iss, error, description } | null
       MorrowSoqlab.finish(answer, { token })             -> Promise<{ ok, status, data, detail, keep }>
       MorrowSoqlab.message(answer)                       -> a sentence for an error coming back from SOQLAB */

  const KEY = "morrow_soqlab_flow";
  const read = () => { try { return JSON.parse(sessionStorage.getItem(KEY) || "null"); } catch { return null; } };
  const write = value => { try { sessionStorage.setItem(KEY, JSON.stringify(value)); return true; } catch { return false; } };
  const clear = () => { try { sessionStorage.removeItem(KEY); } catch { /* storage blocked */ } };

  async function post(path, body, token) {
    const headers = { Accept: "application/json", "Content-Type": "application/json" };
    if (token) headers.Authorization = "Bearer " + token;
    try {
      const res = await fetch(path, { method: "POST", headers, body: JSON.stringify(body), cache: "no-store",
        credentials: "same-origin", referrerPolicy: "no-referrer" });
      let data = null;
      try { data = await res.json(); } catch { data = null; }
      const detail = data && typeof data.detail === "string" ? data.detail
        : res.ok ? "" : res.status === 429 ? "Too many attempts. Wait a minute, then try again." : `The server answered ${res.status}.`;
      return { ok: res.ok, status: res.status, data, detail };
    } catch {
      return { ok: false, status: 0, data: null, detail: "We couldn't reach the server. Try again." };
    }
  }

  async function start(purpose, body = {}, { token = "", keep = null, bearer = "" } = {}) {
    const r = await post("/auth/soqlab/start", { purpose, ...body }, bearer);
    if (!r.ok || !r.data || !r.data.authorize_url) return r;
    if (!write({ flow: r.data.flow, purpose, token, keep, at: Date.now() })) {
      return { ok: false, status: 0, detail: "This browser blocks the storage the sign-in needs. Allow site data for this site, then try again." };
    }
    location.assign(r.data.authorize_url);
    return { ok: true, status: 200, detail: "" };
  }

  function pending() {
    const q = new URLSearchParams(location.search);
    if (!q.has("soqlab_state") && !q.has("soqlab_error")) return null;
    const answer = { code: q.get("soqlab_code") || "", state: q.get("soqlab_state") || "", iss: q.get("soqlab_iss") || "",
      error: q.get("soqlab_error") || "", description: q.get("soqlab_error_description") || "" };
    ["soqlab_code", "soqlab_state", "soqlab_iss", "soqlab_error", "soqlab_error_description"].forEach(k => q.delete(k));
    const rest = q.toString();
    history.replaceState(null, "", location.pathname + (rest ? "?" + rest : "") + location.hash);   // never leave the code in the URL
    return answer;
  }

  async function finish(answer, { bearer = "" } = {}) {
    const saved = read();
    clear();
    if (!saved || !saved.flow || Date.now() - Number(saved.at || 0) > 600000) {
      return { ok: false, status: 0, detail: "This sign-in was started in another tab, or it took too long. Start again.", keep: null };
    }
    const r = await post("/auth/soqlab/callback", { code: answer.code, state: answer.state, iss: answer.iss, flow: saved.flow,
      token: saved.token || "" }, bearer);
    return { ...r, keep: saved.keep || null, purpose: saved.purpose };
  }

  /** What an error coming back from id.soqlab.com means, for the person. */
  function message(answer) {
    const saved = read();
    clear();
    if (answer.error === "access_denied") return saved && saved.purpose === "login" ? "" : "Nothing was changed: you went back from SOQLAB.";
    if (answer.error === "interaction_required" && answer.description === "not_linked") {
      return "This SOQLAB passkey isn't linked to a Morrow account yet. Sign in with your Morrow passkey, then link SOQLAB under Sign-in & recovery.";
    }
    if (answer.error === "login_required") return "Sign in to SOQLAB, then try again.";
    return "SOQLAB couldn't finish the sign-in. Try again.";
  }

  window.MorrowSoqlab = Object.freeze({ start, pending, finish, message });
})();
