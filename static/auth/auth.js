/* Client glue for the gateway's auth pages. Loaded after the SimpleWebAuthn
   browser bundle (global `SimpleWebAuthnBrowser`). No inline scripts: the CSP
   forbids them. Every request is same-origin JSON; the server sets the cookies. */
(function () {
  "use strict";
  var W = window.SimpleWebAuthnBrowser;
  var msg = document.getElementById("msg");

  function say(text, isError) {
    if (!msg) return;
    msg.textContent = text || "";
    msg.className = "msg" + (isError ? " error" : "");
  }

  async function api(method, url, body) {
    var init = { method: method, credentials: "same-origin", headers: {} };
    if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    var res = await fetch(url, init);
    var data = null;
    try { data = await res.json(); } catch (e) { /* no body */ }
    if (!res.ok) {
      var err = new Error((data && data.error) || ("HTTP " + res.status));
      err.code = data && data.error;
      throw err;
    }
    return data;
  }

  function explain(err) {
    var code = err && err.code;
    if (code === "verification_failed") return "The passkey could not be verified. Try again.";
    if (code === "account_not_allowed") return "This account is not allowed to sign in.";
    if (code === "link_expired") return "This enrollment link has expired. Ask for a new one.";
    if (code === "already_registered") return "That passkey is already registered.";
    if (code === "last_passkey") return "The last passkey cannot be deleted.";
    if (code === "rate_limited") return "Too many attempts. Wait a minute and try again.";
    if (code === "no_session") return "Your session has ended. Sign in again.";
    if (code === "reauth_required") return "Confirm it's you with one of your passkeys, then try again.";
    if (err && err.name === "NotAllowedError") return "The passkey prompt was cancelled or timed out.";
    if (err && err.name === "InvalidStateError") return "This authenticator already holds a passkey for this account.";
    return (err && err.message) || "Something went wrong.";
  }

  // Step-up (adding or deleting a passkey): the server allows it for a few
  // minutes after this session proved an existing passkey. The page says how
  // long is left; past that, one passkey prompt comes first.
  var list = document.getElementById("passkeys");
  var manageUntil = list ? Date.now() + 1000 * Number(list.getAttribute("data-manage-for") || 0) - 5000 : 0;

  async function stepUp() {
    say("Confirm it's you with one of your passkeys…");
    var reqOptions = await api("POST", "/auth/passkeys/reauth/options", {});
    var assertion = await W.startAuthentication({ optionsJSON: reqOptions });
    var out = await api("POST", "/auth/passkeys/reauth/verify", assertion);
    manageUntil = Date.now() + 1000 * out.manageFor - 5000;
  }

  /* Run fn(stepped), after a step-up when the window has run out, or once more after one when the server says so. */
  async function withStepUp(fn) {
    var stepped = false;
    if (Date.now() >= manageUntil) {
      await stepUp();
      stepped = true;
    }
    try {
      await fn(stepped);
    } catch (err) {
      if (err.code !== "reauth_required" || stepped) throw err;
      await stepUp();
      await fn(true);
    }
  }

  var form = document.getElementById("flow");
  var go = document.getElementById("go");
  var flow = form && form.getAttribute("data-flow");
  var nameInput = document.getElementById("name");

  if (form && W && !W.browserSupportsWebAuthn()) {
    say("This browser does not support passkeys.", true);
    if (go) go.disabled = true;
  }

  // --- sign-in ---------------------------------------------------------------
  // The challenge is fetched when the page loads, so a tap on the button goes
  // straight to navigator.credentials.get(): WebKit only lets a page ask for a
  // passkey from a tap (or as its one allowance per page load), and a network
  // round trip between the tap and the call can use that up. With an
  // authorization request waiting (data-autostart), the prompt opens on load
  // where the browser allows it - Chrome, Edge, Firefox and Safari 16+ do for
  // a focused, visible page - and the button is the fallback. A refused or
  // cancelled prompt leaves the page waiting for that one tap; it never
  // retries by itself.
  var login = flow === "login" && W && W.browserSupportsWebAuthn();
  // Server challenge lifetime (CHALLENGE_TTL_MS, 120 s) less a margin for the ceremony itself.
  var CHALLENGE_FRESH_MS = 90 * 1000;
  var prepared = null; // { options, at } - a challenge not yet spent on a verify
  var preparing = null;
  var running = false;

  function prepare() {
    if (!preparing) {
      preparing = api("POST", "/auth/login/options", {}).then(function (options) {
        prepared = { options: options, at: Date.now() };
        return prepared;
      }).finally(function () { preparing = null; });
    }
    return preparing;
  }

  function fresh() {
    return prepared && Date.now() - prepared.at < CHALLENGE_FRESH_MS ? prepared : null;
  }

  async function signIn(p, auto) {
    if (running) return;
    running = true;
    if (go) go.disabled = true;
    say("Odotetaan passkeytä… / Waiting for your passkey…");
    try {
      var assertion = await W.startAuthentication({ optionsJSON: p.options });
      prepared = null; // the verify spends the challenge, whatever its outcome
      var next = (await api("POST", "/auth/login/verify", assertion)).next;
      say("Valmis. / Done.");
      location.assign(next);
      return;
    } catch (err) {
      running = false;
      if (go) go.disabled = false;
      if (err && (err.name === "AbortError")) return;
      if (err && err.name === "NotAllowedError") {
        // Cancelled, timed out, or (on load) not allowed without a tap: the same answer either way.
        say(auto ? "Napauta painiketta kirjautuaksesi. / Tap the button to sign in."
                 : "Passkey-kysely peruttiin tai aikakatkaistiin. / The passkey prompt was cancelled or timed out.", !auto);
      } else {
        say(explain(err), true);
      }
      // Have the next challenge ready for the tap.
      if (!fresh()) prepare().catch(function () { /* the tap fetches one */ });
    }
  }

  if (login) {
    var autostart = form.getAttribute("data-autostart") === "1";
    var started = false;
    // Chrome refuses a prompt for a page without focus (a window behind
    // another one): wait for the focus instead of spending the attempt.
    var autoStart = function () {
      if (started || running || document.visibilityState !== "visible") return;
      if (typeof document.hasFocus === "function" && !document.hasFocus()) {
        window.addEventListener("focus", autoStart, { once: true });
        return;
      }
      started = true;
      prepare().then(function (p) { return signIn(p, true); }).catch(function (err) {
        say(explain(err), true);
      });
    };
    prepare().catch(function () { /* the tap fetches one */ });
    if (autostart) {
      if (document.visibilityState === "visible") autoStart();
      else document.addEventListener("visibilitychange", autoStart);
    }
  }

  if (form) {
    form.addEventListener("submit", async function (ev) {
      ev.preventDefault();
      if (login) {
        var p = fresh();
        if (p) return signIn(p, false); // no await before get(): the tap's activation is still live
        if (go) go.disabled = true;
        say("Odotetaan passkeytä… / Waiting for your passkey…");
        try {
          p = await prepare();
        } catch (err) {
          say(explain(err), true);
          if (go) go.disabled = false;
          return;
        }
        if (go) go.disabled = false;
        return signIn(p, false);
      }
      if (go) go.disabled = true;
      say("Waiting for your passkey…");
      try {
        var next;
        if (flow === "enroll") {
          var createOptions = await api("POST", "/auth/enroll/options", {});
          var attestation = await W.startRegistration({ optionsJSON: createOptions });
          next = (await api("POST", "/auth/enroll/verify", { response: attestation, name: nameInput ? nameInput.value : "" })).next;
        } else {
          await withStepUp(async function (stepped) {
            var addOptions = await api("POST", "/auth/passkeys/options", {});
            say("Waiting for your new passkey…");
            var created;
            try {
              created = await W.startRegistration({ optionsJSON: addOptions });
            } catch (err) {
              // Some browsers allow one passkey prompt per tap: the confirmation used it.
              if (stepped && err && err.name === "NotAllowedError") {
                err = new Error("Confirmed. Tap “Add passkey” again to create the new passkey.");
              }
              throw err;
            }
            await api("POST", "/auth/passkeys/verify", { response: created, name: nameInput ? nameInput.value : "" });
          });
          next = location.pathname;
        }
        say("Done.");
        location.assign(next);
      } catch (err) {
        say(explain(err), true);
        if (go) go.disabled = false;
      }
    });
  }

  if (list) {
    list.addEventListener("click", async function (ev) {
      var button = ev.target.closest("button[data-action]");
      if (!button) return;
      var item = button.closest(".passkey");
      var id = item && item.getAttribute("data-id");
      var current = item && item.querySelector(".name") ? item.querySelector(".name").textContent : "";
      if (!id) return;
      try {
        if (button.getAttribute("data-action") === "rename") {
          var name = prompt("New name for this passkey", current);
          if (name === null) return;
          await api("PATCH", "/auth/passkeys/" + encodeURIComponent(id), { name: name });
        } else {
          if (!confirm("Delete the passkey “" + current + "”? Anything signed in with it is signed out: its sessions here, and the webmail and notifications it signed in.")) return;
          await withStepUp(function () {
            return api("DELETE", "/auth/passkeys/" + encodeURIComponent(id));
          });
        }
        location.reload();
      } catch (err) {
        say(explain(err), true);
      }
    });
  }

  var logout = document.getElementById("logout");
  if (logout) {
    logout.addEventListener("click", async function () {
      try {
        var out = await api("POST", "/auth/logout");
        location.assign(out.next || "/auth/login");
      } catch (err) {
        say(explain(err), true);
      }
    });
  }
})();
