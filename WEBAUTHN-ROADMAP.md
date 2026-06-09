# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# WebAuthn Strategy Roadmap (AshAuthentication)

> Goal: deliver an MVP WebAuthn/passkeys strategy in small, reviewable PRs.
>
> This file is intentionally a checklist so we can tick items off as we go.

## Current Status (as of now)

- [x] Basic scaffolding exists in `AshAuthentication.Strategy.WebAuthn` (DSL, strategy protocol impl, plug module)
- [x] A `WebAuthnKey` Spark extension exists (placeholder)
- [x] Example wiring exists in `test/support/example/*` (user + key resource)
- [x] Begin/finish context resolution is split correctly (`begin` resolves from config/request, `finish` reads state-token claims)
- [x] Runtime Wax challenge construction for finish verification is fixed (no `origin_verify_fun` nil crash)
- [x] Registration finish input sanitization is fixed (WebAuthn-only params not forwarded to user create)
- [x] `public_key` can use `AshAuthentication.Type.CoseKey` (transformer/verifier/example aligned)
- [x] DevServer registration flow now completes end-to-end (`register_begin` + `register_finish`)
- [x] DevServer sign-in flow appears to complete end-to-end after adapter/authentication fixes (`sign_in_begin` + `sign_in_finish`)

### Known gaps / issues to address early

- [x] Fix `WebAuthn.Transformer` bug: `maybe_set_register_action_name/1` sets the wrong field
- [x] Fix WebAuthn strategy protocol `tokens_required?/1` (currently references non-existent fields)
- [x] Clean up copy/paste issues (typespecs and docs referencing Password)
- [x] Align `WebAuthn.Plug` with actual WebAuthn phases (remove/adjust reset-related code)
- [x] Decide what to do about `AshAuthentication.Type.CoseKey`:
  - [x] Guard optional dependency usage (`:cbor` is optional) — check added to `WebAuthnKey.Verifier`
  - [x] Fix decode/cast behavior to return decoded term (or remove if not used)

### PR 3 Complete ✅

- [x] Defined `WebAuthnKey` resource contract with required attributes:
  - [x] `credential_id` (binary, unique)
  - [x] `public_key` (binary storage, supports `AshAuthentication.Type.CoseKey`)
  - [x] `sign_count` (integer)
- [x] Added relationship to user (`belongs_to`)
- [x] Created `WebAuthnKey.Info` module for DSL introspection
- [x] Implemented transformer to auto-generate required attributes
- [x] Implemented verifier to validate resource contract
- [x] Added optional fields (`aaguid`, `transports`, `last_used_at`)
- [x] Chose Option B: enforce contract via verifiers (MVP-friendly)
- [x] Removed `user_handle` (belongs on User resource for discoverable credentials)
- [x] Updated DSL schema with WebAuthn-specific field names and comprehensive documentation

---

## MVP Definition (what “usable” means)

The MVP should allow:

- [ ] **Register a credential** for an *existing* user (user already created via password/OAuth/etc.)
- [x] **Sign in** using WebAuthn and receive the same authentication result semantics as other strategies (token in metadata when enabled, etc.) *(validated in DevServer flow; keep hardening with additional tests)*
- [ ] **Persist** credential material in a `key_resource` and use it to authenticate later
- [ ] Core security validation:
  - [ ] challenge binding
  - [ ] rpId/origin validation (as supported by chosen library)
  - [ ] signature verification
  - [ ] sign_count updates (or a documented approach if the library handles it differently)

Explicitly non-MVP / can be deferred:

- [ ] Account creation purely via passkey (no other identity)
- [ ] Attestation trust chain / “trusted authenticators” policy
- [ ] Full device management UX
- [ ] Advanced enterprise attestation and platform-specific policies

---

## Proposed Strategy Shape (MVP)

WebAuthn is inherently multi-step. MVP should use **begin/finish phases**.

### Proposed phases

- [x] `:register_begin`
- [x] `:register_finish`
- [x] `:sign_in_begin`
- [x] `:sign_in_finish`

Notes:

- [x] “Begin” endpoints return `PublicKeyCredential*Options` plus a signed state token.
- [x] “Finish” endpoints verify the client response using the signed state token and return `{:ok, user}`.

---

## PR Plan (small, digestible increments)

### PR 1 — Make the existing scaffolding safe ✅

**Goal:** eliminate runtime traps and obvious correctness issues so we can build forward.

- [x] Fix `WebAuthn.Transformer` register action naming
- [x] Remove/fix `tokens_required?/1` for WebAuthn
- [x] Fix typespec mistakes / copy-paste issues
- [x] Align `WebAuthn.Plug` with actual phases
- [x] Ensure compilation succeeds cleanly
- [x] Add minimal tests asserting:
  - [x] DSL transform produces correct action names
  - [x] Strategy protocol functions don't crash (routes, phases, etc.)

**Exit criteria:** clean compile + WebAuthn modules are internally consistent. ✅

---

### PR 2 — Choose and isolate the WebAuthn crypto/verification implementation ✅

**Goal:** pick a WebAuthn library and hide it behind a stable internal adapter.

- [x] Choose underlying WebAuthn lib (`wax_` library)
- [x] Add a narrow boundary module, `AshAuthentication.WebAuthn.Adapter` behaviour
- [x] Provide a default adapter implementation (`WaxAdapter`)
- [x] Establish how we represent and validate:
  - [x] rpId (via DSL `rp_id` option)
  - [x] origin (via DSL `origin` option passed to adapter)
  - [x] challenge (raw bytes generated by wax_)
  - [x] user handle / discoverable credentials (deferred to later PR)
- [x] Add unit tests with fixtures and/or adapter mocks
- [x] Add compile-time checks for `:cbor` and `:wax_` dependencies

**Exit criteria:** we can generate options and verify responses through the adapter API. ✅

---

### PR 3 — Define the `WebAuthnKey` resource contract (data model MVP) ✅

**Goal:** formalize what `key_resource` must store and validate it.

Minimum required fields:

- [x] `credential_id` (binary) unique
- [x] `public_key` (binary storage; `AshAuthentication.Type.CoseKey` supported)
- [x] `sign_count` (integer)
- [x] Relationship to user (`belongs_to :user, …`) and a usable foreign key

Optional but recommended fields:

- [x] `aaguid`
- [x] `transports`
- [x] `last_used_at`
- [x] `user_handle` (REMOVED - belongs on User resource for discoverable credentials)

Implementation decisions made:

- [x] Chose **Option B**: enforce a contract via verifiers (MVP-friendly)
- [x] Created `AshAuthentication.WebAuthnKey.Info` module for DSL introspection
- [x] Transformer auto-generates required attributes (like TokenResource)
- [x] Verifier validates:
  - [x] Required attributes exist with correct types
  - [x] User relationship exists
  - [x] Unique identity on `credential_id`
  - [x] Optional dependencies (`:cbor`, `:wax_`) are present

**Exit criteria:** the strategy can reliably look up a credential and resolve its user. ✅

---

### PR 4 — Implement begin/finish phases + routes + plugs

**Goal:** deliver a functional HTTP + action interface.

- [x] Implement strategy phases/actions:
  - [x] `register_begin`
  - [x] `register_finish`
  - [x] `sign_in_begin`
  - [x] `sign_in_finish`
- [x] Implement plug handlers for each phase (patterned after Password)
- [x] Decide the request/response shapes:
  - [x] begin returns: options + signed `state`
  - [x] finish accepts: client credential + `state`
- [x] Implement the signed state token format (must include at least challenge + expiry)
  - [x] Decide where signing happens (Jwt vs dedicated signer)
  - [x] Ensure short expiry + replay protection where feasible

**Exit criteria:** a client can complete the full WebAuthn registration and login loop. *(Registration and sign-in loops appear to be working in DevServer.)*

---

### PR 4.5 — Dev server WebAuthn test harness (local development)

**Goal:** enable end-to-end WebAuthn testing in dev without external tooling.

- [x] Add a WebAuthn section to `dev/dev_server/test_page.ex` render output when `:web_authn` is present:
  - [x] Identity input (email/username)
  - [x] Optional display name input (for registration)
  - [x] Buttons: “Register passkey”, “Sign in with passkey”
  - [x] Output `<pre>` to show JSON success/error
  - [x] Embed begin/finish URLs as `data-*` attributes on the section
    - [x] `data-register-begin`, `data-register-finish`
    - [x] `data-signin-begin`, `data-signin-finish`

- [x] Add WebAuthn JS to `dev/dev_server/test_page.html.eex`
  - [x] Insert `<script>` just before `</body>`
  - [x] Provide helpers:
    - [x] base64url encode/decode for ArrayBuffers
    - [x] convert JSON → `PublicKeyCredentialOptions` (challenge/user.id/allowCredentials.id)
    - [x] convert `PublicKeyCredential` → JSON payload
  - [x] Fetch flow (JSON):
    - [x] `register_begin` → `navigator.credentials.create` → `register_finish`
    - [x] `sign_in_begin` → `navigator.credentials.get` → `sign_in_finish`
  - [x] Preserve `state_token` between begin and finish
  - [x] Render server response into `<pre>`

- [ ] Add DevServer UI knobs to exercise different authenticator types
  - [ ] Registration options: `authenticatorAttachment` (platform/cross-platform)
  - [ ] Registration options: `residentKey` + `requireResidentKey`
  - [ ] User verification preference (required/preferred/discouraged)
  - [ ] Optional attestation conveyance setting

- [ ] Add DevServer toggle for discoverable vs identity-required sign-in
  - [ ] Allow empty identity to test discoverable credentials
  - [ ] Show which mode is active in the UI/output

- [ ] Send optional registration/sign-in preferences with begin requests
  - [ ] Only include when set; keep default behavior otherwise

- [ ] JS logic reference (paste into roadmap for clarity)
  - base64url helpers:
    ```js
    const b64uToBuf = (b64u) => {
      const pad = "=".repeat((4 - (b64u.length % 4)) % 4);
      const base64 = (b64u + pad).replace(/-/g, "+").replace(/_/g, "/");
      const bin = atob(base64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes.buffer;
    };

    const bufToB64u = (buf) => {
      const bytes = new Uint8Array(buf);
      let bin = "";
      for (const b of bytes) bin += String.fromCharCode(b);
      return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    };
    ```
  - credential conversion:
    ```js
    const publicKeyFromJSON = (opts) => {
      const pk = { ...opts };
      pk.challenge = b64uToBuf(pk.challenge);
      if (pk.user?.id) pk.user.id = b64uToBuf(pk.user.id);
      if (pk.excludeCredentials) {
        pk.excludeCredentials = pk.excludeCredentials.map((c) => ({ ...c, id: b64uToBuf(c.id) }));
      }
      if (pk.allowCredentials) {
        pk.allowCredentials = pk.allowCredentials.map((c) => ({ ...c, id: b64uToBuf(c.id) }));
      }
      return pk;
    };

    const credentialToJSON = (cred) => ({
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        attestationObject: cred.response.attestationObject && bufToB64u(cred.response.attestationObject),
        authenticatorData: cred.response.authenticatorData && bufToB64u(cred.response.authenticatorData),
        signature: cred.response.signature && bufToB64u(cred.response.signature),
        userHandle: cred.response.userHandle && bufToB64u(cred.response.userHandle)
      }
    });
    ```
  - fetch flow:
    ```js
    const postJSON = async (url, payload) => {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload)
      });
      const json = await resp.json().catch(() => ({}));
      if (!resp.ok) throw json;
      return json;
    };
    ```

- [x] Dev-server note
  - `http://localhost:4000` is a **secure context exception** for WebAuthn
  - If testing off localhost, add HTTPS support to dev server

**Exit criteria:** developers can register + sign in with passkeys in the dev server UI. *(Registration confirmed; sign-in appears to be working.)*

---

### PR 5 — Identity-required vs discoverable credentials (scope control)

**Goal:** pick a first supported sign-in mode.

Recommended order:

- [ ] MVP: implement `require_identity? == true`
  - [ ] `sign_in_begin` requires identity
  - [ ] server restricts `allowCredentials` to that user’s credential IDs
- [ ] Follow-up: implement discoverable (`require_identity? == false`)
  - [ ] `sign_in_begin` can omit identity
  - [ ] `sign_in_finish` finds the user from `credential_id`

**Exit criteria:** at least one sign-in mode is fully functional and tested.

---

### PR 6 — Tests proving correctness

**Goal:** comprehensive tests without needing browser JS.

- [ ] Unit tests:
  - [ ] state token signing/expiry validation
  - [ ] adapter wrapper behavior (mocked)
- [ ] Strategy tests:
  - [x] begin returns options + state
  - [x] finish persists key and returns user
  - [ ] sign_in_finish updates sign_count and/or last_used_at
- [ ] DSL verifier tests:
  - [ ] missing config produces helpful errors
  - [ ] missing attributes/relationship in key_resource is reported

**Exit criteria:** tests cover the happy path and key failure modes.

---

### PR 7 — Minimal docs and example wiring

**Goal:** make it straightforward for app developers to adopt.

- [ ] Document:
  - [ ] required user DSL config
  - [ ] required `key_resource` schema/contract
  - [ ] endpoint sequence (begin → browser API → finish)
  - [ ] suggested frontend tooling (e.g. SimpleWebAuthn)
- [ ] Ensure the `test/support/example` demonstrates a valid setup

**Exit criteria:** a developer can implement WebAuthn in their app with reasonable effort.

---

## Open Questions / Decisions (track here)

- [x] Which underlying WebAuthn library will we use? → `wax_`
- [x] How will we sign and validate the begin/finish "state" token? → JWT-based state token claims are implemented in begin/finish actions
- [x] What should the minimal required `key_resource` fields be for our chosen library? → credential_id, public_key, sign_count + user relationship
- [x] Do we want to auto-generate parts of the key resource (extension transformer) or enforce a contract (verifier-only) for MVP? → Auto-generate + verify (hybrid approach)
- [ ] What's the default stance on `require_identity?`? → (pending PR 5)
- [ ] How should state tokens be structured and signed in begin/finish phases?
