//! Странично-заблокированный буфер для секретов.
//! Не свопится на диск, при Drop заполняется нулями.
//!
//! Windows: VirtualAlloc + VirtualLock.
//! Unix:    mmap + mlock (best-effort).

use std::ptr::NonNull;
use zeroize::Zeroize;

pub struct LockedBuffer {
    ptr: NonNull<u8>,
    len: usize,
    capacity: usize, // page-aligned capacity
}

impl LockedBuffer {
    pub fn new(len: usize) -> Option<Self> {
        if len == 0 {
            return None;
        }
        let capacity = page_align_up(len);
        let ptr = unsafe { platform_alloc_locked(capacity) }?;
        Some(Self { ptr, len, capacity })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        unsafe {
            self.as_mut_slice().zeroize();
            platform_unlock_and_free(self.ptr.as_ptr(), self.capacity);
        }
    }
}

unsafe impl Send for LockedBuffer {}
unsafe impl Sync for LockedBuffer {}

pub struct LockedString {
    buf: LockedBuffer,
    len: usize,
}

impl LockedString {
    #[allow(clippy::should_implement_trait)] // not the same as FromStr (returns Option, infallible input)
    pub fn from_str(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        let mut buf = LockedBuffer::new(bytes.len())?;
        buf.as_mut_slice().copy_from_slice(bytes);
        Some(Self { buf, len: bytes.len() })
    }

    pub fn as_str(&self) -> &str {
        // SAFETY: LockedString is constructed from a valid &str in from_str.
        unsafe { std::str::from_utf8_unchecked(&self.buf.as_slice()[..self.len]) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf.as_slice()[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for LockedString {
    fn drop(&mut self) {
        // Zeroize уже происходит в LockedBuffer::drop
    }
}

impl Clone for LockedString {
    fn clone(&self) -> Self {
        Self::from_str(self.as_str()).expect("locked alloc")
    }
}

impl std::fmt::Debug for LockedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LockedString(<redacted>)")
    }
}

#[cfg(windows)]
mod imp {
    use std::ptr::NonNull;
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, VirtualLock, VirtualUnlock, MEM_COMMIT, MEM_RELEASE,
        MEM_RESERVE, PAGE_READWRITE,
    };

    const PAGE_SIZE: usize = 4096;

    pub unsafe fn platform_alloc_locked(capacity: usize) -> Option<NonNull<u8>> {
        let raw = VirtualAlloc(None, capacity, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if raw.is_null() {
            return None;
        }
        if VirtualLock(raw as *const _, capacity).is_err() {
            let _ = VirtualFree(raw, 0, MEM_RELEASE);
            return None;
        }
        Some(NonNull::new_unchecked(raw as *mut u8))
    }

    pub unsafe fn platform_unlock_and_free(ptr: *mut u8, capacity: usize) {
        let _ = VirtualUnlock(ptr as *const _, capacity);
        let _ = VirtualFree(ptr as *mut _, 0, MEM_RELEASE);
    }

    pub fn page_align_up(len: usize) -> usize {
        (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
    }
}

#[cfg(unix)]
mod imp {
    use std::ptr::NonNull;
    pub unsafe fn platform_alloc_locked(capacity: usize) -> Option<NonNull<u8>> {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            capacity,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if ptr == libc::MAP_FAILED {
            return None;
        }
        // mlock may fail in unprivileged environments (sandboxed CI); best-effort.
        let _ = libc::mlock(ptr, capacity);
        Some(NonNull::new_unchecked(ptr as *mut u8))
    }
    pub unsafe fn platform_unlock_and_free(ptr: *mut u8, capacity: usize) {
        let _ = libc::munlock(ptr, capacity);
        let _ = libc::munmap(ptr as *mut _, capacity);
    }
    pub fn page_align_up(len: usize) -> usize {
        (len + 4095) & !4095
    }
}

pub use imp::page_align_up;
use imp::{platform_alloc_locked, platform_unlock_and_free};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locked_buffer_basic() {
        let mut buf = LockedBuffer::new(64).expect("alloc failed");
        assert_eq!(buf.len(), 64);
        buf.as_mut_slice()[0] = 0x42;
        buf.as_mut_slice()[63] = 0x99;
        assert_eq!(buf.as_slice()[0], 0x42);
        assert_eq!(buf.as_slice()[63], 0x99);
        drop(buf);
    }

    #[test]
    fn test_locked_buffer_zero_len() {
        assert!(LockedBuffer::new(0).is_none());
    }

    #[test]
    fn test_locked_string_basic() {
        let s = LockedString::from_str("hunter2").expect("alloc");
        assert_eq!(s.as_str(), "hunter2");
        assert_eq!(s.len(), 7);
    }

    #[test]
    fn test_locked_string_clone() {
        let s = LockedString::from_str("password123").expect("alloc");
        let s2 = s.clone();
        assert_eq!(s.as_str(), s2.as_str());
        // Each clone is an independent buffer.
        drop(s);
        assert_eq!(s2.as_str(), "password123");
    }
}
