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

  if (form) {
    form.addEventListener("submit", async function (ev) {
      ev.preventDefault();
      if (go) go.disabled = true;
      say("Waiting for your passkey…");
      try {
        var next;
        if (flow === "login") {
          var reqOptions = await api("POST", "/auth/login/options", {});
          var assertion = await W.startAuthentication({ optionsJSON: reqOptions });
          next = (await api("POST", "/auth/login/verify", assertion)).next;
        } else if (flow === "enroll") {
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
