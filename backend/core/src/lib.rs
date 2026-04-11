use std::ffi::c_void;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce, Tag};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyRuntimeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyModule};
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use sha2::Sha256;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};
use zeroize::Zeroize;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_LANES: u32 = 4;
const BLIND_INDEX_INFO: &[u8] = b"bitnet:blind-index:title:v1";

type BlindIndexMac = Hmac<Sha256>;

fn runtime_error(message: impl Into<String>) -> PyErr {
    PyRuntimeError::new_err(message.into())
}

fn value_error(message: impl Into<String>) -> PyErr {
    PyValueError::new_err(message.into())
}

fn type_error(message: impl Into<String>) -> PyErr {
    PyTypeError::new_err(message.into())
}

fn lock_region(ptr: *mut u8, len: usize) -> PyResult<()> {
    if len == 0 {
        return Ok(());
    }

    let locked = unsafe { VirtualLock(ptr.cast::<c_void>(), len) };
    if locked == 0 {
        let code = unsafe { GetLastError() };
        return Err(runtime_error(format!(
            "VirtualLock failed for {} bytes (Win32={code})",
            len
        )));
    }

    Ok(())
}

fn unlock_region(ptr: *mut u8, len: usize) {
    if len == 0 {
        return;
    }

    unsafe {
        VirtualUnlock(ptr.cast::<c_void>(), len);
    }
}

struct LockedBytes {
    secret: Option<SecretBox<Vec<u8>>>,
    locked_len: usize,
}

impl LockedBytes {
    fn empty() -> Self {
        Self {
            secret: None,
            locked_len: 0,
        }
    }

    fn from_vec(mut data: Vec<u8>) -> PyResult<Self> {
        lock_region(data.as_mut_ptr(), data.len())?;
        Ok(Self {
            locked_len: data.len(),
            secret: Some(SecretBox::new(Box::new(data))),
        })
    }

    fn with_len(len: usize) -> PyResult<Self> {
        Self::from_vec(vec![0u8; len])
    }

    fn from_slice(data: &[u8]) -> PyResult<Self> {
        let mut out = Self::with_len(data.len())?;
        out.as_mut_slice()?.copy_from_slice(data);
        Ok(out)
    }

    fn duplicate(&self) -> PyResult<Self> {
        Self::from_slice(self.as_slice()?)
    }

    fn len(&self) -> usize {
        self.secret
            .as_ref()
            .map(|secret| secret.expose_secret().len())
            .unwrap_or(0)
    }

    fn is_closed(&self) -> bool {
        self.secret.is_none()
    }

    fn as_slice(&self) -> PyResult<&[u8]> {
        let secret = self
            .secret
            .as_ref()
            .ok_or_else(|| runtime_error("LockedBuffer is already closed"))?;
        Ok(secret.expose_secret().as_slice())
    }

    fn as_mut_slice(&mut self) -> PyResult<&mut [u8]> {
        let secret = self
            .secret
            .as_mut()
            .ok_or_else(|| runtime_error("LockedBuffer is already closed"))?;
        Ok(secret.expose_secret_mut().as_mut_slice())
    }

    fn close(&mut self) {
        if let Some(mut secret) = self.secret.take() {
            let (ptr, len) = {
                let buf = secret.expose_secret();
                (buf.as_ptr() as *mut u8, buf.len())
            };

            secret.expose_secret_mut().zeroize();
            unlock_region(ptr, len);

            self.locked_len = 0;
        }
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        self.close();
    }
}

#[pyclass(module = "bitnet_crypto_rs")]
struct LockedBuffer {
    inner: LockedBytes,
}

impl LockedBuffer {
    fn from_vec(data: Vec<u8>) -> PyResult<Self> {
        Ok(Self {
            inner: LockedBytes::from_vec(data)?,
        })
    }

    fn from_slice(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: LockedBytes::from_slice(data)?,
        })
    }

    fn as_slice(&self) -> PyResult<&[u8]> {
        self.inner.as_slice()
    }

    fn duplicate_inner(&self) -> PyResult<Self> {
        Ok(Self {
            inner: self.inner.duplicate()?,
        })
    }
}

#[pymethods]
impl LockedBuffer {
    fn duplicate(&self) -> PyResult<Self> {
        self.duplicate_inner()
    }

    fn close(&mut self) {
        self.inner.close();
    }

    fn copy_into(&self, py: Python<'_>, target: &Bound<'_, PyAny>) -> PyResult<()> {
        let mut buffer = PyBuffer::<u8>::get(target)?;
        if buffer.readonly() {
            return Err(type_error(
                "target buffer must be writable (bytearray or writable memoryview)",
            ));
        }
        if !buffer.is_c_contiguous() || buffer.item_size() != 1 {
            return Err(type_error(
                "target buffer must be C-contiguous with item_size == 1",
            ));
        }

        let source = self.as_slice()?;
        if buffer.len_bytes() != source.len() {
            return Err(value_error(format!(
                "target buffer length {} does not match source length {}",
                buffer.len_bytes(),
                source.len()
            )));
        }

        buffer.copy_from_slice(py, source)?;
        Ok(())
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    #[getter]
    fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    fn __repr__(&self) -> String {
        format!(
            "<LockedBuffer len={} closed={}>",
            self.inner.len(),
            self.inner.is_closed()
        )
    }
}

fn with_py_buffer<R>(
    obj: &Bound<'_, PyAny>,
    require_writable: bool,
    f: impl FnOnce(&[u8]) -> PyResult<R>,
) -> PyResult<R> {
    let buffer = PyBuffer::<u8>::get(obj)?;
    if !buffer.is_c_contiguous() || buffer.item_size() != 1 {
        return Err(type_error(
            "buffer must be C-contiguous with item_size == 1",
        ));
    }
    if require_writable && buffer.readonly() {
        return Err(type_error(
            "buffer must be writable (bytearray or writable memoryview)",
        ));
    }

    let slice = unsafe {
        std::slice::from_raw_parts(buffer.buf_ptr().cast::<u8>(), buffer.len_bytes())
    };

    f(slice)
}

fn with_secret_input<R>(
    obj: &Bound<'_, PyAny>,
    require_writable: bool,
    f: impl FnOnce(&[u8]) -> PyResult<R>,
) -> PyResult<R> {
    if let Ok(locked) = obj.extract::<PyRef<'_, LockedBuffer>>() {
        return f(locked.as_slice()?);
    }

    with_py_buffer(obj, require_writable, f)
}

#[pyfunction]
fn lock_bytes(data: &Bound<'_, PyAny>) -> PyResult<LockedBuffer> {
    with_py_buffer(data, true, LockedBuffer::from_slice)
}

#[pyfunction]
fn generate_locked_random(length: usize) -> PyResult<LockedBuffer> {
    if length == 0 {
        return Err(value_error("length must be greater than zero"));
    }

    let mut locked = LockedBuffer {
        inner: LockedBytes::with_len(length)?,
    };
    OsRng.fill_bytes(locked.inner.as_mut_slice()?);
    Ok(locked)
}

#[pyfunction]
fn argon2_derive_key(master_pwd: &Bound<'_, PyAny>, salt: &Bound<'_, PyAny>) -> PyResult<LockedBuffer> {
    with_py_buffer(master_pwd, true, |password_bytes| {
        with_secret_input(salt, false, |salt_bytes| {
            if salt_bytes.len() < 8 {
                return Err(value_error("salt must contain at least 8 bytes"));
            }

            let params = Params::new(
                ARGON2_MEMORY_KIB,
                ARGON2_TIME_COST,
                ARGON2_LANES,
                Some(KEY_LEN),
            )
            .map_err(|err| runtime_error(format!("invalid Argon2 parameters: {err}")))?;

            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let mut derived = LockedBuffer {
                inner: LockedBytes::with_len(KEY_LEN)?,
            };

            argon2
                .hash_password_into(password_bytes, salt_bytes, derived.inner.as_mut_slice()?)
                .map_err(|err| runtime_error(format!("Argon2id derivation failed: {err}")))?;

            Ok(derived)
        })
    })
}

#[pyfunction]
fn aes_gcm_encrypt(
    py: Python<'_>,
    key: PyRef<'_, LockedBuffer>,
    plaintext: &Bound<'_, PyAny>,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>, Py<PyBytes>)> {
    let key_bytes = key.as_slice()?;
    if key_bytes.len() != KEY_LEN {
        return Err(value_error(format!("AES-256-GCM requires a {KEY_LEN}-byte key")));
    }

    with_secret_input(plaintext, true, |plain_bytes| {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));

        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let mut ciphertext = plain_bytes.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut ciphertext)
            .map_err(|err| runtime_error(format!("AES-GCM encryption failed: {err}")))?;

        Ok((
            PyBytes::new(py, &ciphertext).unbind(),
            PyBytes::new(py, &nonce).unbind(),
            PyBytes::new(py, tag.as_slice()).unbind(),
        ))
    })
}

#[pyfunction]
fn aes_gcm_decrypt(
    key: PyRef<'_, LockedBuffer>,
    ciphertext: &Bound<'_, PyAny>,
    nonce: &Bound<'_, PyAny>,
    tag: &Bound<'_, PyAny>,
) -> PyResult<LockedBuffer> {
    let key_bytes = key.as_slice()?;
    if key_bytes.len() != KEY_LEN {
        return Err(value_error(format!("AES-256-GCM requires a {KEY_LEN}-byte key")));
    }

    with_secret_input(ciphertext, false, |ciphertext_bytes| {
        with_secret_input(nonce, false, |nonce_bytes| {
            with_secret_input(tag, false, |tag_bytes| {
                if nonce_bytes.len() != NONCE_LEN {
                    return Err(value_error(format!(
                        "nonce must be exactly {NONCE_LEN} bytes"
                    )));
                }
                if tag_bytes.len() != TAG_LEN {
                    return Err(value_error(format!("tag must be exactly {TAG_LEN} bytes")));
                }

                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));

                let mut plaintext = LockedBuffer::from_slice(ciphertext_bytes)?;
                let auth_tag = Tag::<Aes256Gcm>::clone_from_slice(tag_bytes);

                cipher
                    .decrypt_in_place_detached(
                        Nonce::from_slice(nonce_bytes),
                        b"",
                        plaintext.inner.as_mut_slice()?,
                        &auth_tag,
                    )
                    .map_err(|_| runtime_error("AES-GCM authentication failed"))?;

                Ok(plaintext)
            })
        })
    })
}

#[pyfunction]
fn generate_blind_index_hmac(
    key: PyRef<'_, LockedBuffer>,
    title: &Bound<'_, PyAny>,
) -> PyResult<String> {
    let key_bytes = key.as_slice()?;
    if key_bytes.len() != KEY_LEN {
        return Err(value_error(format!(
            "blind-index derivation requires a {KEY_LEN}-byte master key"
        )));
    }

    with_py_buffer(title, true, |title_bytes| {
        let hkdf = Hkdf::<Sha256>::new(None, key_bytes);
        let mut derived_index_key = [0u8; KEY_LEN];
        hkdf.expand(BLIND_INDEX_INFO, &mut derived_index_key)
            .map_err(|err| runtime_error(format!("HKDF expansion failed: {err}")))?;

        let mut mac = BlindIndexMac::new_from_slice(&derived_index_key)
            .map_err(|err| runtime_error(format!("HMAC initialization failed: {err}")))?;
        mac.update(title_bytes);
        let blind_index = mac.finalize().into_bytes();

        derived_index_key.zeroize();

        Ok(hex::encode(blind_index))
    })
}

#[pymodule]
fn bitnet_crypto_rs(_py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<LockedBuffer>()?;
    module.add_function(wrap_pyfunction!(lock_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(generate_locked_random, module)?)?;
    module.add_function(wrap_pyfunction!(argon2_derive_key, module)?)?;
    module.add_function(wrap_pyfunction!(aes_gcm_encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(aes_gcm_decrypt, module)?)?;
    module.add_function(wrap_pyfunction!(generate_blind_index_hmac, module)?)?;
    Ok(())
}
