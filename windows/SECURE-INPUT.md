# Windows secure-screen input

## Status and scope

This implementation is under review. The normal Windows application and the secure-input helper are separate packages. The helper installer builds, but automatic discovery/download of that package and its release-feed integration are not wired into the application yet.

The intended use is unlocking an existing signed-in Windows session and responding to UAC consent or credential prompts. Windows authentication is still required. The feature does not change UAC policy, so enabling it does not turn ordinary Yes/No prompts into password prompts.

This does not provide access before the first sign-in after a restart, BitLocker unlock, biometric authentication, or generation of the secure Ctrl+Alt+Delete sequence. The worker checks for Winlogon before privileged injection and uses a user-level handoff on Default; it does not intentionally control elevated Default-desktop applications. Desktop-transition timing still requires review.

## Setup and use

Use matching application/client builds containing this feature. Existing released clients may not have the enrollment controls.

Replace any earlier experimental helper with the new separate package before testing enrollment. The application does not automatically migrate the old prototype helper; an existing old helper executable can otherwise be selected instead of the new enrollment implementation.

1. Pair the controlling device with the Windows computer normally.
2. On Windows, select **Allow on Windows secure screens**. If the helper is missing, choose the separate secure-input installer and approve its administrator prompt. The application then requests elevation for device enrollment. Obtain this initial package from the trusted release source; the package-selection dialog does not verify a downloaded package's signature itself.
3. On the controlling device, choose **Allow Secure Screens**.
4. Compare the six-digit number shown on the device with the number in the elevated Windows enrollment window. Confirm on both sides only when the numbers match. Enrollment expires after two minutes.
5. Re-enable keyboard capture on the controlling device if it was turned off to display the comparison. Connect normally and use the keyboard on the lock screen or UAC prompt.

Authorizing one device does not authorize every device in the application's ordinary pairing store. To enroll another, choose **Allow another device on secure screens** on Windows and repeat the comparison for that device.

A device authorized for secure screens should be treated as having administrator access to the machine. Protect that device and its private key accordingly. Authorization is held by the per-machine component, not scoped by the ordinary application's pairing file.

### Keyboard modes and outages

After enrollment, keyboard commands remain encrypted to the protected component on both normal and secure desktops. On Default, the service returns the validated input to the ordinary application, which uses its existing user-level SendInput path. On Winlogon, the SYSTEM worker injects the input itself.

A previously enrolled controller pauses keyboard input when the protected session is unavailable or its identity cannot be verified. It does not automatically send plaintext keys through the ordinary application. Input is not queued for later replay. The client attempts to re-establish an available protected session after service or worker failures.

**Use Normal Keyboard Only** is an explicit choice on the controlling device, with local confirmation. It removes that controller's stored service pin and returns to ordinary keyboard transport. Secure-screen input is then unavailable. This choice does not revoke the device key in the Windows service's authorization list. Individual-device revocation has no management API/UI yet; disabling the Windows feature clears all secure authorizations independently of ordinary pairing.

Turning off **Allow on Windows secure screens** on Windows stops and disables the service and clears its authorized device list. Ordinary pairings, application settings and NVDA settings are preserved. A controller that still has a service pin will pause keyboard input; choose normal-only mode there if ordinary control is wanted. Re-enabling secure access requires enrollment again.

The separate **Portputer Secure Input** uninstall entry removes the service, its package files and its protected data, including the service identity and update staging. The ordinary application has a separate uninstall entry.

## Trust boundary

The ordinary application handles networking, the outer control connection, audio, clipboard and ordinary pairing. It is outside the secure-input authorization boundary. A process able to modify paired.json or inject into that user-level application must not thereby obtain secure-screen input authority.

The protected component holds:

- A static Noise private key in the Windows ProgramData known folder, under `Portputer Secure Input\Private\service.key`. Its file DACL grants access to SYSTEM.
- A separate device-key list in `Private\trusted.json`, accessible to SYSTEM and Administrators.
- Protected staging for helper updates.

Administrators and SYSTEM are trusted. These ACLs do not protect against an administrator taking ownership or replacing privileged components.

The device establishes a second `Noise_XX_25519_ChaChaPoly_BLAKE2s` session with the protected component inside the existing control connection. Its prologue is `portputer secure input 2`. The ordinary application relays the handshake and encrypted input records. The device pins the service key after successful enrollment. The service checks the device key against its protected authorization list, including when accepting input.

Enrollment requires both an encrypted confirmation from the device and a confirmation from an elevated pipe client with Administrators membership. The elevated confirmation is bound to the full handshake hash and the enrollment connection. The six-digit comparison is derived independently on each side from that hash. The controlling client ignores outer-server notices that attempt to impersonate its secure-input confirmation notices.

### Routing and remaining risks

The ordinary application cannot authorize privileged input by claiming that a desktop is secure. The desktop-state hint is informational. An enrolled controller encrypts its keys regardless of that hint. The protected component checks the actual input desktop before deciding whether to inject on Winlogon, return input for Default, or refuse it.

Default-desktop input is intentionally available to the ordinary application after this check. Its injection remains subject to the application's normal Windows integrity level. The implementation chooses SYSTEM injection only after checking Winlogon. The desktop check and injection/handoff are separate operations; rapid-transition races and held-key behavior still require focused testing and maintainer review.

A compromised ordinary application can drop, delay or disrupt traffic and audio. Encryption and authorization do not establish which UAC prompt a person intended to approve. Malware may time a prompt to coincide with legitimate remote input; the remote user must check the prompt, using the available audio or other feedback. A compromised authorized controller or Windows administrator is outside this protection boundary.

A local-session isolation review remains outstanding. The rewritten pipe handler checks elevation/admin membership for management requests but does not enforce the original pipe-client session constraint for relay requests. Workers share the machine's service identity and device list, and the inner channel does not bind a Windows session identifier. Whether an untrusted relay can redirect an enrolled controller's input into an unintended session needs assessment before merge. Unknown devices still require enrollment; no cross-session exploit is claimed or tested successfully.

The implementation needs maintainer security review and the remaining acceptance tests below before release.

## Local transport and lifecycle

The helper has no network listener. Workers run as SYSTEM in logged-in interactive Windows sessions. The service handles session-change notifications and reconciles workers, with backoff after repeated failures.

Each worker publishes a random pipe name in a protected per-session discovery file. Pipes reject remote clients. Ordinary local clients can relay encrypted records; executable-path checks are not used to authorize secure input. The client verifies SYSTEM pipe ownership and uses identification-only SQOS.

Pipe I/O uses overlapped operations and bounded frames, with explicit failure replies. Startup failures after handler registration report Stopped with a service-specific error. Service shutdown signals workers and waits for exit, with a force-stop fallback. The installer waits for the service to stop before replacing its executable.

Held-key tracking is discarded across desktop switches, rather than transferring releases onto a different desktop. Disconnect and idle handling attempt releases only on the permitted secure desktop. Held-key behavior during abrupt crashes and rapid switches still needs acceptance testing.

Current bounds include 12 KiB inner frames, eight concurrent local connections per worker, two-minute enrollment windows, three enrollment opens per window and at most 64 authorized device keys. Text commands are limited and split to account for JSON escaping. Failed input is not automatically replayed.

No firewall rules, UAC policy changes, desktop ACL changes, kernel driver or additional UIAccess privileges are introduced. Probe commands and VM test executables are not shipped.

## Installation and updates

The separate elevated NSIS package writes the helper directly to the Windows Program Files known folder, under `Portputer Secure Input`. It contains the service executable and license, not a second copy of Portputer or its DLLs. The normal application remains in its per-user installation. Runtime paths use Windows known-folder APIs or the protected process's image directory, not inherited ProgramFiles environment variables.

The ordinary application opens a downloaded update with its own permissions and sends bounded package bytes over the pipe. SYSTEM does not open a caller-supplied download path. An upload belongs to its connection, is limited to 64 MiB and two minutes, and incomplete uploads are removed on disconnect or expiry.

After the protected copy is complete, the service verifies its Ed25519 signature against the compiled release public key. It reads package identity and build number from the signed executable's version resource, requires the `Portputer Secure Input` product identity and a build newer than the installed build, then starts the protected updater. Caller-supplied version claims are not trusted.

The installer preserves a disabled service during package replacement. It keeps a temporary previous helper for rollback and removes that temporary copy after a successful install. The rollback failure paths need further fault-injection testing. A service-open failure now aborts replacement unless the error specifically means the service does not exist.

The Windows build currently has no Authenticode signing. The helper update path uses the project's existing EdDSA release key. Initial package sourcing, signing/distribution, build-script integration and the second package's appcast entries remain maintainer integration work. This branch does not yet provide automatic helper-update discovery through the UI.

### Building the separate package for review

The normal `windows/build.sh` still builds the helper executable but does not produce or discover its separate installer yet. The new installer definition is `windows/secure-input-installer.nsi`.

Build the helper with `PORTPUTER_BUILD_NUMBER` set to the intended increasing release build. Stage `portputer-input-service.exe` and `LICENSE.txt` in a dedicated folder. Invoke NSIS with `VERSION`, `VERSION_NUMBERS`, `BUILD`, `STAGE` and `OUTFILE` definitions, as for the existing application installer. Use the same build number for compilation, the installer resource and release metadata. Do not add the helper executable back to the per-user application package.

Ordinary automated tests run with `cargo test -p portputer-core -p portputer-windows-input`. The built-package resource test is intentionally ignored in that run: set `PORTPUTER_TEST_PACKAGE` to the installer path and `PORTPUTER_TEST_PACKAGE_BUILD` to its build, then run `cargo test -p portputer-windows-input --lib reads_signed_package_identity_and_build_resource -- --ignored`.

## Validation of this revision

The current branch passed 51 ordinary Rust checks, the separately invoked package-resource check, and the native waiting-dialog smoke check. Scoped Clippy passed with allowances for pre-existing upstream findings. Windows release app/helper and installer builds passed. The native Mac build and 40 shared-core checks passed; its final Swift source compiles. Android resources were parsed, but Android/iOS native builds and screen-reader acceptance remain outstanding.

Manual Mac-to-Windows acceptance passed password unlocking, reconnecting to an already locked session, UAC cancellation and approval, NVDA audio through the tested transitions, protected-service recovery without replay, normal-only cancellation/confirmation, and disabling while ordinary input/audio continued. Locked reconnect used a Mac app restart workaround for the discovery/address-field issues below.

Technical VM checks covered protected-store access, independent enrollment comparisons, standard/medium-token management rejection, unknown-device rejection, tampering/replay, protocol mismatch, startup failure, service/worker recovery, helper replacement including disabled-state preservation, unsigned/update-owner/interruption rejection and uninstall cleanup. Two real user sessions had one worker each; a disposable session's worker crash recovered without restarting the other worker. Three stop/start cycles removed all worker processes and discovery files.

Real sign-out exposed a stale discovery publication when Windows terminated a worker before its own cleanup. The service now removes the publication after confirming worker exit. The dead-worker regression and a second real sign-out passed, preserving the other user's worker. The disposable account, profile and credentials were removed after testing.

Ordinary Shift/Ctrl/Alt with repeated non-printing input released cleanly in a standard-user session. Additional secure-desktop held-key stress is not yet accepted: the first external test stopped at a rejected input, and its only targeted retry aborted on a held-key baseline condition before secure input. A later state check found the four test keys released; no persistent stuck-key diagnosis is claimed. Full rapid-switch/crash/held-key coverage and atomic check/injection guarantees are not established. A proposed external cross-session negative test was blocked before execution and was not bypassed or counted as passed.

Still outstanding: local-session isolation/security review, complete rapid-transition/held-key and rollback-fault matrices, positive official signed update/feed execution, per-device revocation UI/API, and mobile/native accessibility acceptance. Functional success does not replace those checks.

## Deferred macOS issues

- Secure-screen-specific accessibility limitation: ready/paused/normal-only status text is visible, but VoiceOver status announcements were not reliable in manual testing. The attempted announcement API change did not pass acceptance. No further fix is included in this PR.
- Computer list fails to repopulate after disconnect: potentially general discovery/view behavior; restart restored the list and preserved pairing. No general discovery fix included.
- Manual address field rejects input after capture/disconnect: potentially general focus/capture behavior; the relationship to this feature is unproven. No address-field/KeyCapture fix included.
- Power/Lock failure matches the first-responder issue described in [Aaron's draft PR #3](https://github.com/aaron-gh/portputer/pull/3). That fix is not imported. RDP locking was used to continue the secure-screen tests.

These remain deferred separately from the tested secure-input functions. The native enrollment and normal-only confirmation UI changes in this branch are limited to this feature.
