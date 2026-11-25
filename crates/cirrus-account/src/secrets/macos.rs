//! Noninteractive Data Protection Keychain credentials; no login-keychain fallback.

use core_foundation::{
    array::CFArray,
    base::{CFType, CFTypeRef, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::CFDictionary,
    string::{CFString, CFStringRef},
};
use security_framework_sys::{
    access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    base as status, item as sec,
    keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemUpdate},
};
use zeroize::Zeroizing;

use super::{AccountData, CredentialError, LegacyAccount, StoredAccount};
use crate::ownership::credentials::Context;

const SERVICE: &str = "org.cirrusdrive.account.v1";
const MAX_SECRET: usize = 131_072;
type Result<T> = std::result::Result<T, CredentialError>;

// SecBase.h constants absent from security-framework-sys 2.11.0. Values and
// meanings are from Apple's published header, not inferred from error prose.
const USER_CANCELED: i32 = -128;
const MISSING_ENTITLEMENT: i32 = -34018;
const NOT_AVAILABLE: i32 = -25291;
const READ_ONLY: i32 = -25292;
const INTERACTION_NOT_ALLOWED: i32 = -25308;
const INTERACTION_REQUIRED: i32 = -25315;

// Missing in security-framework-sys 2.11.0. These are real exported CFStringRef
// symbols from Apple's Security/SecItem.h, not reconstructed string constants.
// UI-Fail is deprecated but supported; no claim of LAContext integration.
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrAccessible: CFStringRef;
    static kSecAttrSynchronizable: CFStringRef;
    static kSecUseAuthenticationUI: CFStringRef;
    static kSecUseAuthenticationUIFail: CFStringRef;
    static kSecValuePersistentRef: CFStringRef;
}

macro_rules! symbol {
    ($name:path) => {{
        // SAFETY: every invocation names an immutable, framework-owned,
        // nonnull CFStringRef exported by Security on the macOS 15+ baseline.
        unsafe { CFString::wrap_under_get_rule($name) }
    }};
}

pub(crate) struct Store {
    context: Context,
}

struct Existing {
    reference: CFData,
    account: StoredAccount,
}

impl Store {
    pub(crate) fn open(context: &Context) -> Result<Self> {
        context.revalidate()?;
        Ok(Self {
            context: context.clone(),
        })
    }

    // Accessibility is checked in returned attributes, not used to hide a
    // matching item with the wrong protection policy. Only OS metadata outside
    // the security-relevant fields may vary; this is not Linux's exact map.
    fn query(&self, instance: &str) -> Vec<(CFString, CFType)> {
        vec![
            (
                symbol!(sec::kSecClass),
                symbol!(sec::kSecClassGenericPassword).as_CFType(),
            ),
            (
                symbol!(sec::kSecAttrService),
                CFString::new(SERVICE).as_CFType(),
            ),
            (
                symbol!(sec::kSecAttrAccount),
                CFString::new(instance).as_CFType(),
            ),
            (
                symbol!(sec::kSecAttrAccessGroup),
                CFString::new(self.context.access_group()).as_CFType(),
            ),
            (
                symbol!(sec::kSecUseDataProtectionKeychain),
                CFBoolean::true_value().as_CFType(),
            ),
            (
                symbol!(kSecAttrSynchronizable),
                CFBoolean::false_value().as_CFType(),
            ),
            (
                symbol!(kSecUseAuthenticationUI),
                symbol!(kSecUseAuthenticationUIFail).as_CFType(),
            ),
        ]
    }

    fn existing(&self, instance: &str) -> Result<Option<Existing>> {
        self.context.revalidate()?;
        let mut pairs = self.query(instance);
        for key in [
            symbol!(sec::kSecReturnAttributes),
            symbol!(sec::kSecReturnData),
            symbol!(sec::kSecReturnPersistentRef),
        ] {
            pairs.push((key, CFBoolean::true_value().as_CFType()));
        }
        pairs.push((
            symbol!(sec::kSecMatchLimit),
            symbol!(sec::kSecMatchLimitAll).as_CFType(),
        ));
        let query = CFDictionary::from_CFType_pairs(&pairs);
        let mut raw: CFTypeRef = std::ptr::null();
        // SAFETY: query owns all retained CF keys/values; raw is an out pointer.
        // CopyMatching returns an owned CF object, adopted exactly once below.
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut raw) };
        let result = if raw.is_null() {
            None
        } else {
            // SAFETY: nonnull Copy result is +1 regardless of concrete type.
            Some(unsafe { CFType::wrap_under_create_rule(raw) })
        };
        if status == status::errSecItemNotFound {
            return Ok(None);
        }
        checked_status(status)?;
        let result = result.ok_or_else(invalid_result)?;
        let array = result.downcast::<CFArray>().ok_or_else(invalid_result)?;
        if array.len() != 1 {
            return Err(CredentialError::invalid(
                "multiple or invalid matching account secrets require manual resolution",
            ));
        }
        let item = array.get(0).ok_or_else(invalid_result)?;
        if (*item).is_null() {
            return Err(invalid_result());
        }
        // SAFETY: CFArray contains CF objects owned by the result. Retain the
        // element as untyped CFType before checking its actual dictionary type.
        let item = unsafe { CFType::wrap_under_get_rule(*item) };
        let attrs = item.downcast::<CFDictionary>().ok_or_else(invalid_result)?;
        for (key, expected) in [
            (
                symbol!(sec::kSecClass),
                symbol!(sec::kSecClassGenericPassword),
            ),
            (symbol!(sec::kSecAttrService), CFString::new(SERVICE)),
            (symbol!(sec::kSecAttrAccount), CFString::new(instance)),
            (
                symbol!(sec::kSecAttrAccessGroup),
                CFString::new(self.context.access_group()),
            ),
            (
                symbol!(kSecAttrAccessible),
                symbol!(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
            ),
        ] {
            let value = attribute(&attrs, &key)?;
            if value.downcast::<CFString>().as_ref() != Some(&expected) {
                return Err(CredentialError::invalid(
                    "matching account secret has unexpected Keychain attributes",
                ));
            }
        }
        let synchronizable = attribute(&attrs, &symbol!(kSecAttrSynchronizable))?;
        if synchronizable.downcast::<CFBoolean>().as_ref() != Some(&CFBoolean::false_value())
            || attrs.contains_key(&symbol!(sec::kSecAttrAccessControl).as_CFTypeRef())
        {
            return Err(CredentialError::invalid(
                "matching account secret has unexpected Keychain protection",
            ));
        }
        let reference = data_attribute(&attrs, &symbol!(kSecValuePersistentRef))?;
        let data = data_attribute(&attrs, &symbol!(sec::kSecValueData))?;
        // Check framework CFData length before bytes()/allocation/copy. Rust
        // serialization/copies are zeroized; framework-owned memory is not.
        let secret = Zeroizing::new(data.bytes().to_vec());
        let account = StoredAccount::decode(&secret, instance).map_err(CredentialError::invalid)?;
        Ok(Some(Existing { reference, account }))
    }

    pub(crate) fn load(&self, instance: &str) -> Result<AccountData> {
        self.load_for_sign_in(instance)?
            .ok_or_else(|| CredentialError::invalid("account is not connected"))?
            .current()
            .map_err(CredentialError::invalid)
    }

    pub(crate) fn load_for_sign_in(&self, instance: &str) -> Result<Option<StoredAccount>> {
        self.existing(instance)
            .map(|item| item.map(|item| item.account))
    }

    pub(crate) fn save(&self, account: &AccountData) -> Result<()> {
        self.save_checked(account, None)
    }

    pub(crate) fn replace_legacy(
        &self,
        account: &AccountData,
        previous: &LegacyAccount,
    ) -> Result<()> {
        self.save_checked(account, Some(previous))
    }

    fn save_checked(&self, account: &AccountData, replace: Option<&LegacyAccount>) -> Result<()> {
        self.context.require_writer()?;
        // Validate the existing payload while the SAME writer fence is held.
        let existing = self.existing(&account.instance)?;
        StoredAccount::check_save(
            existing.as_ref().map(|item| &item.account),
            account,
            replace,
        )
        .map_err(CredentialError::invalid)?;
        let encoded = Zeroizing::new(
            serde_json::to_vec(account)
                .map_err(|_| CredentialError::invalid("cannot encode account secret"))?,
        );
        if encoded.len() > MAX_SECRET {
            return Err(CredentialError::invalid(
                "account secret exceeds the size limit",
            ));
        }
        let data = CFData::from_buffer(&encoded);
        let mut pairs = self.query(&account.instance);
        self.context.require_writer()?;
        let status = if let Some(existing) = existing {
            pairs.push((
                symbol!(kSecValuePersistentRef),
                existing.reference.as_CFType(),
            ));
            pairs.push((
                symbol!(kSecAttrAccessible),
                symbol!(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly).as_CFType(),
            ));
            let query = CFDictionary::from_CFType_pairs(&pairs);
            let update =
                CFDictionary::from_CFType_pairs(&[(symbol!(sec::kSecValueData), data.as_CFType())]);
            // SAFETY: both dictionaries retain their objects throughout the
            // call. Only secret data is updated on the validated exact item.
            let status =
                unsafe { SecItemUpdate(query.as_concrete_TypeRef(), update.as_concrete_TypeRef()) };
            if status == status::errSecItemNotFound {
                return Err(CredentialError::invalid(
                    "account secret disappeared during save; manual resolution required",
                ));
            }
            status
        } else {
            pairs.push((
                symbol!(kSecAttrAccessible),
                symbol!(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly).as_CFType(),
            ));
            pairs.push((symbol!(sec::kSecValueData), data.as_CFType()));
            let attributes = CFDictionary::from_CFType_pairs(&pairs);
            // SAFETY: attributes retains all objects. No result requested; null
            // is the documented optional output, not an unowned returned item.
            unsafe { SecItemAdd(attributes.as_concrete_TypeRef(), std::ptr::null_mut()) }
        };
        checked_status(status)
    }
}

fn invalid_result() -> CredentialError {
    CredentialError::invalid("Keychain returned invalid account secret metadata")
}

fn attribute(dict: &CFDictionary, key: &CFString) -> Result<CFType> {
    let value = dict.find(key.as_CFTypeRef()).ok_or_else(invalid_result)?;
    if (*value).is_null() {
        return Err(invalid_result());
    }
    // SAFETY: a CFDictionary result owns CF objects; retain a found, nonnull
    // value as CFType. Every caller downcasts before reading concrete contents.
    Ok(unsafe { CFType::wrap_under_get_rule(*value) })
}

fn data_attribute(dict: &CFDictionary, key: &CFString) -> Result<CFData> {
    let value = attribute(dict, key)?
        .downcast::<CFData>()
        .ok_or_else(invalid_result)?;
    if value.len() <= 0 || value.len() as u64 > MAX_SECRET as u64 {
        return Err(CredentialError::invalid(
            "account secret exceeds the size limit or is empty",
        ));
    }
    Ok(value)
}

fn checked_status(status: i32) -> Result<()> {
    match status {
        status::errSecSuccess => Ok(()),
        status::errSecDuplicateItem => Err(CredentialError::invalid(
            "account secret changed during save; manual resolution required",
        )),
        status::errSecAuthFailed => Err(CredentialError::invalid(
            "Keychain authentication was denied; authorize access in the containing app",
        )),
        USER_CANCELED => Err(CredentialError::invalid("Keychain access was cancelled")),
        MISSING_ENTITLEMENT => Err(CredentialError::invalid(
            "the app is missing its required Keychain access-group entitlement",
        )),
        INTERACTION_NOT_ALLOWED | INTERACTION_REQUIRED => Err(CredentialError::invalid(
            "Keychain requires user interaction; unlock or authorize access in the containing app",
        )),
        READ_ONLY => Err(CredentialError::invalid("Keychain cannot be modified")),
        status::errSecParam | status::errSecBadReq => Err(CredentialError::invalid(
            "Keychain rejected the credential query or protection policy",
        )),
        status::errSecUnimplemented => Err(CredentialError::invalid(
            "the requested Keychain operation is unsupported",
        )),
        NOT_AVAILABLE => Err(CredentialError::unavailable(
            "Keychain service is temporarily unavailable",
        )),
        // Only known service availability enters automatic Retry/backoff.
        // Action-required and unknown failures enter Attention, never spin or
        // become absence; an unknown status does not promise that unlock fixes it.
        _ => Err(CredentialError::invalid(
            "Keychain operation failed; review credential access in the containing app",
        )),
    }
}
