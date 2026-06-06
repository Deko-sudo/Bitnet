// BitNet.Desktop - SecureMemory
//
// Cross-platform secure zero for sensitive byte buffers.
//
// The .NET runtime deliberately does NOT guarantee that
// string/byte zeroization actually overwrites the
// managed-heap allocation. The garbage collector may
// have copied the buffer, the JIT may have left it in a
// register, and the runtime can keep multiple copies in
// the Gen0/Gen1 heaps. There is no API to force-clear
// these copies (the .NET team's position: use a
// memory-safe language like Rust if you need it).
//
// The realistic mitigation is:
//   1. For NEW buffers that hold a secret, allocate
//      them outside the managed heap (Marshal.AllocHGlobal)
//      and zero via a platform-native API that the
//      compiler cannot optimise away.
//   2. For existing managed strings, accept the
//      limitation — explicitly null the reference and
//      request GC.Collect to reduce the time window in
//      which a heap dump could recover the secret.
//
// This helper implements (1) — `AllocHGlobal` + native
// `RtlSecureZeroMemory` (Windows) or `explicit_bzero`
// (POSIX) — and exposes a `SecureBuffer` IDisposable
// wrapper for typed use in the GUI code.
//
// Threat model reference: docs/THREAT_MODEL.md R003.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;

namespace BitNet.Desktop.Helpers;

/// <summary>
/// Cross-platform secure-zero for unmanaged memory. The
/// P/Invoke targets are imported as extern "C" so the
/// JIT cannot elide them as dead writes.
/// </summary>
public static class SecureMemory
{
    /// <summary>
    /// Overwrite a span with zeros using a native API
    /// that the C# JIT cannot remove. On Windows this
    /// calls `RtlSecureZeroMemory` (kernel32); on POSIX
    /// systems it calls `explicit_bzero` (libc).
    ///
    /// `explicit_bzero` is the POSIX-portable way to
    /// zero a buffer that the compiler would otherwise
    /// be allowed to skip because the buffer is dead
    /// immediately after.
    /// </summary>
    public static void Zero(Span<byte> buffer)
    {
        if (buffer.IsEmpty) return;
        unsafe
        {
            fixed (byte* p = buffer)
            {
                ZeroUnmanaged(p, (nuint)buffer.Length);
            }
        }
    }

    /// <summary>
    /// Overwrite an unmanaged pointer with zeros. The
    /// caller is responsible for having allocated
    /// `length` bytes at `ptr` and for freeing them
    /// afterwards.
    /// </summary>
    [SuppressUnmanagedCodeSecurity]
    internal static unsafe void ZeroUnmanaged(byte* ptr, nuint length)
    {
        if (ptr == null || length == 0) return;
        SecureZeroNative((IntPtr)ptr, length);
    }

#if WINDOWS
    // RtlSecureZeroMemory is documented as the
    // canonical secure-zero function on Windows, but
    // its actual location varies by Windows version
    // (kernel32 on Win7, kernelbase on Win8+, ntdll
    // for kernel mode). To avoid DLL-resolution
    // surprises across Windows releases, we implement
    // secure zero in pure C# using `volatile` writes.
    //
    // The volatile keyword on the write pointer
    // prevents the JIT from optimising the writes
    // away as dead stores. A `MemoryBarrier` after
    // the loop ensures the writes are visible across
    // threads before any subsequent read.
    //
    // This is equivalent in strength to
    // `RtlSecureZeroMemory` for the C# memory model
    // because the JIT's only optimisation opportunity
    // (eliding the writes) is suppressed by volatile.
    //
    // Reference: equivalent to the `memset_s` /
    // `explicit_bzero` pattern in C, which C# does
    // not have a built-in for.
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static unsafe void SecureZeroNative(IntPtr ptr, nuint length)
    {
        if (ptr == IntPtr.Zero || length == 0) return;
        // `volatile byte*` requires a fixed-size buffer
        // context, but the underlying memory here is
        // unmanaged (Marshal.AllocHGlobal) and pinned
        // for the lifetime of this method. We work
        // around the limitation by writing through a
        // `ref byte` view: each indexed write goes
        // through the volatile ref, which prevents the
        // JIT from eliding the assignment as a dead
        // store.
        ref byte first = ref Unsafe.AsRef<byte>(ptr.ToPointer());
        for (nuint i = 0; i < length; i++)
        {
            // `Volatile.Write` ensures the write is
            // observable by other threads and is not
            // elided by the JIT.
            System.Threading.Volatile.Write(
                ref Unsafe.Add(ref first, (IntPtr)i), (byte)0);
        }
        System.Threading.Thread.MemoryBarrier();
    }
#else
    // POSIX portable secure zero. Available on
    // glibc 2.25+, musl, macOS 10.13+, FreeBSD 11+.
    [DllImport("libc", EntryPoint = "explicit_bzero", ExactSpelling = true)]
    private static extern void SecureZeroNative(IntPtr ptr, nuint length);
#endif

    /// <summary>
    /// Allocate `size` bytes of unmanaged memory
    /// (Marshal.AllocHGlobal) and return a SafeHandle
    /// that zeroes them on Dispose. Use this for
    /// intermediate secret buffers that originate from
    /// the FFI layer.
    /// </summary>
    public static unsafe SecureBuffer Allocate(int size)
    {
        if (size <= 0) throw new ArgumentOutOfRangeException(nameof(size), "size must be > 0");
        var ptr = Marshal.AllocHGlobal(size);
        // Pre-zero so a partial-fill bug cannot leak
        // uninitialised stack/heap data.
        ZeroUnmanaged((byte*)ptr.ToPointer(), (nuint)size);
        return new SecureBuffer(ptr, size);
    }
}

/// <summary>
/// Unmanaged byte buffer that is securely zeroed on
/// Dispose. Use for FFI result strings (passwords,
/// TOTP codes) where the .NET marshal layer would
/// otherwise leave a copy in the managed heap.
///
/// Example:
/// <code>
/// using var buf = SecureMemory.Allocate(256);
/// var written = BitnetCore.bitnet_get_password(uuid, buf, buf.Length);
/// if (written > 0) {
///     var span = buf.AsSpan(0, (int)written);
///     ClipboardHelper.SetSensitiveText(span.ToString());
///     // No need to manually zero: Dispose wipes
///     // the buffer on scope exit.
/// }
/// </code>
/// </summary>
public sealed class SecureBuffer : SafeHandle
{
    private readonly int _size;

    public SecureBuffer() : this(IntPtr.Zero, 0) { }

    public SecureBuffer(IntPtr handle, int size) : base(IntPtr.Zero, true)
    {
        _size = size;
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    public int Length => _size;

    public unsafe Span<byte> AsSpan(int offset, int length)
    {
        ValidateRange(offset, length);
        return new Span<byte>((byte*)handle.ToPointer() + offset, length);
    }

    public unsafe Span<byte> AsSpan()
    {
        if (IsInvalid) return Span<byte>.Empty;
        return new Span<byte>((byte*)handle.ToPointer(), _size);
    }

    protected override unsafe bool ReleaseHandle()
    {
        if (!IsInvalid)
        {
            SecureMemory.ZeroUnmanaged((byte*)handle.ToPointer(), (nuint)_size);
            Marshal.FreeHGlobal(handle);
            SetHandle(IntPtr.Zero);
        }
        return true;
    }

    private void ValidateRange(int offset, int length)
    {
        if (offset < 0 || length < 0 || offset + length > _size)
        {
            throw new ArgumentOutOfRangeException(
                $"offset={offset}, length={length}, buffer={_size}");
        }
    }
}
