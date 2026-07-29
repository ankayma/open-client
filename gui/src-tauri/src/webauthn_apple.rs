//! Native FIDO2 security-key ceremony for Apple platforms (E-7 StepUp Phase 3, AAL3).
//!
//! Why this module exists at all: `navigator.credentials.*` in the frontend cannot
//! register or assert a roaming security key inside Tauri's WKWebView. That is a
//! platform limit, not a configuration mistake —
//!
//!   "Apple does not support FIDO2 security keys for the WebAuthn flow using a
//!    WKWebView."
//!   [T:developers.yubico.com/WebAuthn/Supporting_FIDO2_Security_Keys_on_iOS_or_iPadOS/FAQ]
//!
//! — confirmed on hardware 2026-07-29: `create()` rejects with `NotAllowedError` and
//! the system log shows no AuthenticationServices activity at all, i.e. WebKit refuses
//! before the OS is ever asked. Apple's exception is passkeys on iOS 16.1+; roaming USB
//! keys are outside it. Full analysis + rejected alternatives:
//! `docs/webauthn-security-key-decision.md`.
//!
//! So the ceremony runs here instead, through `AuthenticationServices`. The **wire
//! format does not change**: this takes the same `publicKey` options the control plane
//! already sends and returns the same credential JSON the frontend already posts back,
//! so `stepup.rs` (webauthn-rs) needs no change and the webview keeps owning the UI.
//!
//! The RP ID handed to `ASAuthorizationSecurityKeyPublicKeyCredentialProvider` is
//! validated by the OS against the `webcredentials:` associated domain — which is what
//! the `com.apple.developer.associated-domains` entitlement is genuinely for. See
//! `docs/macos-associated-domains.md` (including how claiming it without an embedded
//! provisioning profile made two releases unlaunchable).
//!
//! Availability floor is `macos(12.0)` / `ios(15.0)`, read from
//! `AuthenticationServices.framework/Headers/ASAuthorizationSecurityKeyPublicKeyCredentialProvider.h`
//! (`API_AVAILABLE(macos(12.0), ios(15.0))`). `tauri.conf.json` sets no macOS minimum,
//! so `is_supported()` gates at runtime rather than trusting the deployment target. [T]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{define_class, AllocAnyThread, DefinedClass, MainThreadMarker, MainThreadOnly};
use objc2_authentication_services::{
    ASAuthorization, ASAuthorizationController, ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding,
    ASAuthorizationPublicKeyCredentialAssertion, ASAuthorizationPublicKeyCredentialParameters,
    ASAuthorizationPublicKeyCredentialRegistration,
    ASAuthorizationPublicKeyCredentialRegistrationRequest, ASAuthorizationRequest,
    ASAuthorizationSecurityKeyPublicKeyCredentialAssertion,
    ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor,
    ASAuthorizationSecurityKeyPublicKeyCredentialDescriptorTransportBluetooth,
    ASAuthorizationSecurityKeyPublicKeyCredentialDescriptorTransportNFC,
    ASAuthorizationSecurityKeyPublicKeyCredentialDescriptorTransportUSB,
    ASAuthorizationSecurityKeyPublicKeyCredentialProvider,
    ASAuthorizationSecurityKeyPublicKeyCredentialRegistration, ASPublicKeyCredential,
};
use objc2_foundation::{NSArray, NSData, NSError, NSString};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::sync::mpsc::{sync_channel, SyncSender};

/// The `ASPresentationAnchor` the system's security-key sheet attaches to.
///
/// macOS gets this from Tauri (`WebviewWindow::ns_window`), but Tauri exposes no
/// `UIWindow` on iOS, so find the key window ourselves. Deliberately via
/// `connectedScenes` rather than `UIApplication.windows`: the latter is deprecated
/// since iOS 15 and returns nothing useful in a scene-based app. The deployment target
/// is iOS 16 (`tauri.conf.json`), so `connectedScenes` is always available and needs no
/// fallback. `respondsToSelector:` avoids having to compare against `UIWindowScene`,
/// which would mean pulling in UIKit bindings for one check.
///
/// Must be called on the main thread — `UIApplication` is main-thread-only — which
/// `start_on_main` already guarantees.
#[cfg(target_os = "ios")]
pub fn presentation_anchor() -> *mut AnyObject {
    use objc2::runtime::AnyClass;
    use objc2::{msg_send, sel};

    unsafe {
        let Some(cls) = AnyClass::get(c"UIApplication") else {
            return std::ptr::null_mut();
        };
        let app: *mut AnyObject = msg_send![cls, sharedApplication];
        if app.is_null() {
            return std::ptr::null_mut();
        }
        let scenes: *mut AnyObject = msg_send![app, connectedScenes];
        if scenes.is_null() {
            return std::ptr::null_mut();
        }
        let all: *mut AnyObject = msg_send![scenes, allObjects];
        if all.is_null() {
            return std::ptr::null_mut();
        }
        let scene_count: usize = msg_send![all, count];
        let mut first_window: *mut AnyObject = std::ptr::null_mut();
        for i in 0..scene_count {
            let scene: *mut AnyObject = msg_send![all, objectAtIndex: i];
            let responds: bool = msg_send![scene, respondsToSelector: sel!(windows)];
            if !responds {
                continue;
            }
            let windows: *mut AnyObject = msg_send![scene, windows];
            if windows.is_null() {
                continue;
            }
            let count: usize = msg_send![windows, count];
            for j in 0..count {
                let w: *mut AnyObject = msg_send![windows, objectAtIndex: j];
                let is_key: bool = msg_send![w, isKeyWindow];
                if is_key {
                    return w;
                }
                if first_window.is_null() {
                    first_window = w;
                }
            }
        }
        // No key window (can happen briefly during scene setup) — any window still gives
        // the sheet something to attach to, which beats failing the ceremony outright.
        first_window
    }
}

/// Whether this OS can run the native ceremony at all. Callers must check first —
/// `tauri.conf.json` pins no macOS deployment target, so the binary may legally run
/// somewhere older than the 12.0 floor, where the class simply does not exist.
pub fn is_supported() -> bool {
    // Resolving the class by name is the honest test: it exists iff the framework on
    // *this* machine vends it. A compile-time cfg would only describe the SDK we built
    // against, which is not the same question. [T:objc2 AnyClass::get]
    objc2::runtime::AnyClass::get(c"ASAuthorizationSecurityKeyPublicKeyCredentialProvider")
        .is_some()
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|e| format!("malformed base64url in ceremony options: {e}"))
}

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn nsdata(bytes: &[u8]) -> Retained<NSData> {
    NSData::with_bytes(bytes)
}

fn data_to_vec(d: Retained<NSData>) -> Vec<u8> {
    d.to_vec()
}

/// Pull a required string out of the server's options blob with an error that says
/// which field was missing — these blobs are big and a bare `None` is unusable.
fn req_str(v: &Value, path: &str) -> Result<String, String> {
    v.pointer(path)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("ceremony options missing {path}"))
}

/// What the delegate hands back to the blocked caller.
type Outcome = Result<Value, String>;

struct DelegateIvars {
    /// `sync_channel(1)`; taken on first use so a double callback cannot send twice.
    tx: RefCell<Option<SyncSender<Outcome>>>,
    /// `ASPresentationAnchor` — `NSWindow` on macOS, `UIWindow` on iOS. Borrowed, not
    /// owned: the window outlives the ceremony because the ceremony is modal over it.
    anchor: *mut AnyObject,
}

define_class!(
    // SAFETY: NSObject imposes no subclassing requirements, and this type has no Drop.
    #[unsafe(super(NSObject))]
    // AuthenticationServices calls back on the main thread and wants a presentation
    // anchor, so the delegate is main-thread-only by construction.
    #[thread_kind = MainThreadOnly]
    #[name = "AnkaymaWebAuthnDelegate"]
    #[ivars = DelegateIvars]
    struct Delegate;

    unsafe impl NSObjectProtocol for Delegate {}

    unsafe impl ASAuthorizationControllerDelegate for Delegate {
        #[unsafe(method(authorizationController:didCompleteWithAuthorization:))]
        fn did_complete(&self, _controller: &ASAuthorizationController, auth: &ASAuthorization) {
            self.finish(unsafe { credential_to_json(auth) });
        }

        #[unsafe(method(authorizationController:didCompleteWithError:))]
        fn did_error(&self, _controller: &ASAuthorizationController, error: &NSError) {
            // `ASAuthorizationError.canceled` (1001) is the user dismissing the sheet or
            // never touching the key. Surface it as its own message: the UI treats a
            // cancel as "try again", not as a broken install.
            let code = error.code();
            let msg = error.localizedDescription().to_string();
            self.finish(Err(if code == 1001 {
                "cancelled".to_owned()
            } else {
                format!("security key ceremony failed ({code}): {msg}")
            }));
        }
    }

    unsafe impl ASAuthorizationControllerPresentationContextProviding for Delegate {
        #[unsafe(method(presentationAnchorForAuthorizationController:))]
        fn anchor(&self, _controller: &ASAuthorizationController) -> *mut AnyObject {
            self.ivars().anchor
        }
    }
);

impl Delegate {
    fn finish(&self, outcome: Outcome) {
        // Take the sender so a second callback (AuthenticationServices should not, but
        // the delegate outlives one call) is dropped instead of panicking on a closed
        // channel.
        if let Some(tx) = self.ivars().tx.borrow_mut().take() {
            let _ = tx.send(outcome);
        }
    }
}

/// Convert whichever credential the OS produced into the exact JSON shape the control
/// plane already accepts from the browser path — see `frontend/app-gui/src/lib/webauthn.ts`.
///
/// # Safety
/// `auth` must be a live `ASAuthorization` delivered by the delegate callback.
unsafe fn credential_to_json(auth: &ASAuthorization) -> Outcome {
    let credential = unsafe { auth.credential() };
    let any: &AnyObject = credential.as_ref();

    if let Some(reg) =
        any.downcast_ref::<ASAuthorizationSecurityKeyPublicKeyCredentialRegistration>()
    {
        let raw_id = data_to_vec(unsafe { reg.credentialID() });
        let client_data = data_to_vec(unsafe { reg.rawClientDataJSON() });
        // Attestation is optional in the protocol; webauthn-rs rejects a registration
        // without it, so fail here with a readable reason rather than posting a blob
        // the server will reject for a reason nobody can trace back to this line.
        let attestation = unsafe { reg.rawAttestationObject() }
            .ok_or("the authenticator returned no attestation object")?;
        return Ok(json!({
            "id": b64url(&raw_id),
            "rawId": b64url(&raw_id),
            "type": "public-key",
            "response": {
                "attestationObject": b64url(&data_to_vec(attestation)),
                "clientDataJSON": b64url(&client_data),
            },
        }));
    }

    if let Some(assertion) =
        any.downcast_ref::<ASAuthorizationSecurityKeyPublicKeyCredentialAssertion>()
    {
        let raw_id = data_to_vec(unsafe { assertion.credentialID() });
        let user_handle = data_to_vec(unsafe { assertion.userID() });
        return Ok(json!({
            "id": b64url(&raw_id),
            "rawId": b64url(&raw_id),
            "type": "public-key",
            "response": {
                "authenticatorData": b64url(&data_to_vec(unsafe { assertion.rawAuthenticatorData() })),
                "clientDataJSON": b64url(&data_to_vec(unsafe { assertion.rawClientDataJSON() })),
                "signature": b64url(&data_to_vec(unsafe { assertion.signature() })),
                // webauthn-rs treats userHandle as optional; an empty one means "not
                // provided" and must be null, not "".
                "userHandle": if user_handle.is_empty() { Value::Null } else { json!(b64url(&user_handle)) },
            },
        }));
    }

    Err("the ceremony returned a credential type we did not ask for".to_owned())
}

/// Map the server's `excludeCredentials` / `allowCredentials` descriptor list.
///
/// Transports are advisory. We pass every transport the key might use rather than
/// echoing the server's list, because webauthn-rs frequently omits it and an empty
/// transport array is interpreted by the OS as "no way to reach this credential",
/// which would silently defeat `excludeCredentials`. `[A? — revisit if the OS starts
/// honouring a narrower list usefully]`
unsafe fn descriptors(
    list: Option<&Vec<Value>>,
) -> Result<Retained<NSArray<ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor>>, String> {
    let mut out = Vec::new();
    for entry in list.into_iter().flatten() {
        let id = entry
            .get("id")
            .and_then(Value::as_str)
            .ok_or("credential descriptor without an id")?;
        let transports = NSArray::from_slice(&[
            unsafe { ASAuthorizationSecurityKeyPublicKeyCredentialDescriptorTransportUSB },
            unsafe { ASAuthorizationSecurityKeyPublicKeyCredentialDescriptorTransportNFC },
            unsafe { ASAuthorizationSecurityKeyPublicKeyCredentialDescriptorTransportBluetooth },
        ]);
        let desc = unsafe {
            ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor::initWithCredentialID_transports(
                ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor::alloc(),
                &nsdata(&b64url_decode(id)?),
                &transports,
            )
        };
        out.push(desc);
    }
    Ok(NSArray::from_retained_slice(&out))
}

/// Build the registration request from the control plane's `publicKey` options and run
/// it. `options` is the `options.publicKey` object from `/stepup/webauthn/register/start`.
unsafe fn build_registration(options: &Value) -> Result<Retained<ASAuthorizationRequest>, String> {
    let rp_id = req_str(options, "/rp/id")?;
    let challenge = b64url_decode(&req_str(options, "/challenge")?)?;
    let user_id = b64url_decode(&req_str(options, "/user/id")?)?;
    let user_name = req_str(options, "/user/name")?;
    let display_name = options
        .pointer("/user/displayName")
        .and_then(Value::as_str)
        .unwrap_or(&user_name)
        .to_owned();

    let provider = unsafe {
        ASAuthorizationSecurityKeyPublicKeyCredentialProvider::initWithRelyingPartyIdentifier(
            ASAuthorizationSecurityKeyPublicKeyCredentialProvider::alloc(),
            &NSString::from_str(&rp_id),
        )
    };
    let request = unsafe {
        provider.createCredentialRegistrationRequestWithChallenge_displayName_name_userID(
            &nsdata(&challenge),
            &NSString::from_str(&display_name),
            &NSString::from_str(&user_name),
            &nsdata(&user_id),
        )
    };

    // pubKeyCredParams -> credentialParameters. The server decides the algorithm set;
    // dropping it here would let the authenticator pick something webauthn-rs then
    // refuses, so this is not optional.
    let algs: Vec<Retained<ASAuthorizationPublicKeyCredentialParameters>> = options
        .get("pubKeyCredParams")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|p| p.get("alg").and_then(Value::as_i64))
                .map(|alg| unsafe {
                    ASAuthorizationPublicKeyCredentialParameters::initWithAlgorithm(
                        ASAuthorizationPublicKeyCredentialParameters::alloc(),
                        alg as isize,
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    if algs.is_empty() {
        return Err("ceremony options carried no pubKeyCredParams".to_owned());
    }
    unsafe { request.setCredentialParameters(&NSArray::from_retained_slice(&algs)) };

    let exclude = options.get("excludeCredentials").and_then(Value::as_array);
    unsafe { request.setExcludedCredentials(&*descriptors(exclude)?) };

    // AAL3 wants a real attestation to bind the factor to hardware (A.1.10). The server
    // asks for it explicitly; mirror whatever it asked rather than hard-coding, so a
    // server-side policy change does not need a client release.
    // `ASAuthorizationPublicKeyCredentialAttestationKind` is a typedef of NSString, so
    // the server's string ("none"/"indirect"/"direct") passes straight through. [T:
    // ASAuthorizationPublicKeyCredentialConstants.rs — `pub type … = NSString`]
    let attestation = options
        .get("attestation")
        .and_then(Value::as_str)
        .unwrap_or("none");
    unsafe { request.setAttestationPreference(&NSString::from_str(attestation)) };

    Ok(Retained::into_super(request))
}

/// Build the assertion request. `options` is `options.publicKey` from
/// `/stepup/webauthn/authenticate/start`.
unsafe fn build_assertion(options: &Value) -> Result<Retained<ASAuthorizationRequest>, String> {
    let rp_id = req_str(options, "/rpId").or_else(|_| req_str(options, "/rp/id"))?;
    let challenge = b64url_decode(&req_str(options, "/challenge")?)?;

    let provider = unsafe {
        ASAuthorizationSecurityKeyPublicKeyCredentialProvider::initWithRelyingPartyIdentifier(
            ASAuthorizationSecurityKeyPublicKeyCredentialProvider::alloc(),
            &NSString::from_str(&rp_id),
        )
    };
    let request =
        unsafe { provider.createCredentialAssertionRequestWithChallenge(&nsdata(&challenge)) };

    let allow = options.get("allowCredentials").and_then(Value::as_array);
    unsafe { request.setAllowedCredentials(&*descriptors(allow)?) };

    Ok(Retained::into_super(request))
}

#[derive(Clone, Copy)]
pub enum Ceremony {
    Register,
    Authenticate,
}

thread_local! {
    /// The controller and its delegate must outlive `performRequests`, which returns
    /// immediately — the OS calls back much later, once the user has touched the key.
    /// Dropping them at the end of the main-thread closure would tear the ceremony down
    /// before it started. Parking exactly one pair here keeps them alive without leaking
    /// per ceremony: a new ceremony replaces the old, and step-up is inherently one at a
    /// time. Main-thread-only by construction, which is why this is a thread_local and
    /// not a static.
    static IN_FLIGHT: RefCell<Option<(Retained<Delegate>, Retained<ASAuthorizationController>)>> =
        const { RefCell::new(None) };
}

/// Start a ceremony. **Must run on the main thread** — the delegate is `MainThreadOnly`
/// and this puts a system sheet on screen. Returns immediately; the result arrives on
/// `tx` when the user acts.
///
/// Split from the wait deliberately: `performRequests` is asynchronous and its callback
/// is delivered on the main run loop, so blocking for the result on the main thread
/// would deadlock — the run loop could never deliver the callback we were waiting for.
/// The caller therefore hops here via `AppHandle::run_on_main_thread` and blocks on the
/// receiver from a worker thread.
pub fn start_on_main(
    anchor: *mut AnyObject,
    options: &Value,
    which: Ceremony,
    tx: SyncSender<Outcome>,
) {
    let Some(mtm) = MainThreadMarker::new() else {
        let _ = tx.send(Err(
            "the security-key ceremony must be started from the main thread".to_owned(),
        ));
        return;
    };

    let built = unsafe {
        match which {
            Ceremony::Register => build_registration(options),
            Ceremony::Authenticate => build_assertion(options),
        }
    };
    let request = match built {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.send(Err(e));
            return;
        }
    };

    let delegate = Delegate::alloc(mtm).set_ivars(DelegateIvars {
        tx: RefCell::new(Some(tx)),
        anchor,
    });
    let delegate: Retained<Delegate> = unsafe { objc2::msg_send![super(delegate), init] };

    let controller = unsafe {
        ASAuthorizationController::initWithAuthorizationRequests(
            ASAuthorizationController::alloc(),
            &NSArray::from_retained_slice(&[request]),
        )
    };
    unsafe {
        controller.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        controller.setPresentationContextProvider(Some(ProtocolObject::from_ref(&*delegate)));
        controller.performRequests();
    }

    IN_FLIGHT.with(|slot| *slot.borrow_mut() = Some((delegate, controller)));
}

/// Channel pair for one ceremony. Capacity 1 so the delegate never blocks the main
/// thread on send, even if the caller has already given up.
pub fn channel() -> (SyncSender<Outcome>, std::sync::mpsc::Receiver<Outcome>) {
    sync_channel::<Outcome>(1)
}
