$p = Get-Process BitNet.Wpf -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $p -or $p.MainWindowHandle -eq 0) {
    Write-Host "WPF window not found, trying Desktop..."
    $p = Get-Process BitNet.Desktop -ErrorAction SilentlyContinue | Select-Object -First 1
}
if (-not $p -or $p.MainWindowHandle -eq 0) {
    Write-Host "No BitNet window found."
    exit 1
}

Write-Host "Fixing window: PID=$($p.Id), HWND=$($p.MainWindowHandle), Title='$($p.MainWindowTitle)'"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WinFix {
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool InvalidateRect(IntPtr hWnd, IntPtr lpRect, bool bErase);
    [DllImport("user32.dll")] public static extern bool UpdateWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool RedrawWindow(IntPtr hWnd, IntPtr lprcUpdate, IntPtr hrgnUpdate, uint flags);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);
    public static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
    public const uint SWP_SHOWWINDOW = 0x0040;
    public const uint SWP_FRAMECHANGED = 0x0020;
    public const uint RDW_INVALIDATE = 0x0001;
    public const uint RDW_UPDATENOW = 0x0100;
    public const uint RDW_FRAME = 0x0400;
    public const uint RDW_ALLCHILDREN = 0x0080;
}
"@

$h = $p.MainWindowHandle

# Restore, foreground, topmost
[WinFix]::ShowWindow($h, 9)
[WinFix]::SetForegroundWindow($h)
[WinFix]::SetWindowPos($h, [WinFix]::HWND_TOPMOST, 100, 100, 800, 600, [WinFix]::SWP_SHOWWINDOW -bor [WinFix]::SWP_FRAMECHANGED)

# Force repaint
[WinFix]::InvalidateRect($h, [IntPtr]::Zero, $true)
[WinFix]::UpdateWindow($h)
[WinFix]::RedrawWindow($h, [IntPtr]::Zero, [IntPtr]::Zero, [WinFix]::RDW_INVALIDATE -bor [WinFix]::RDW_UPDATENOW -bor [WinFix]::RDW_FRAME -bor [WinFix]::RDW_ALLCHILDREN)

# Move slightly to force recomposition
Start-Sleep -Milliseconds 200
[WinFix]::MoveWindow($h, 150, 150, 800, 600, $true)
Start-Sleep -Milliseconds 200
[WinFix]::MoveWindow($h, 100, 100, 800, 600, $true)

# Remove topmost
[WinFix]::SetWindowPos($h, [IntPtr]::Zero, 0, 0, 0, 0, [WinFix]::SWP_SHOWWINDOW -bor [WinFix]::SWP_NOMOVE -bor [WinFix]::SWP_NOSIZE)

Write-Host "Window fix applied. Check if content is visible now."
