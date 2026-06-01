$exe = "D:\BitNet\bitnet\BitNet.Wpf\bin\Debug\net9.0-windows\BitNet.Wpf.exe"
$proc = Start-Process -FilePath $exe -PassThru
Write-Host "Started PID: $($proc.Id)"
Start-Sleep -Seconds 5

$proc.Refresh()
Write-Host "MainWindowHandle: $($proc.MainWindowHandle)"
Write-Host "MainWindowTitle: $($proc.MainWindowTitle)"
Write-Host "Responding: $($proc.Responding)"

if ($proc.MainWindowHandle -ne 0) {
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class WinApi {
        [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
        [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
        public static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
        public static readonly IntPtr HWND_NOTOPMOST = new IntPtr(-2);
        public const uint SWP_SHOWWINDOW = 0x0040;
        public const uint SWP_NOSIZE = 0x0001;
        public const uint SWP_NOMOVE = 0x0002;
        public const uint SWP_FRAMECHANGED = 0x0020;
    }
"@

    [WinApi]::ShowWindow($proc.MainWindowHandle, 9)  # SW_RESTORE
    [WinApi]::SetForegroundWindow($proc.MainWindowHandle)
    [WinApi]::SetWindowPos($proc.MainWindowHandle, [WinApi]::HWND_TOPMOST, 0, 0, 0, 0, [WinApi]::SWP_SHOWWINDOW -bor [WinApi]::SWP_NOMOVE -bor [WinApi]::SWP_NOSIZE)
    Start-Sleep -Milliseconds 500
    [WinApi]::SetWindowPos($proc.MainWindowHandle, [WinApi]::HWND_NOTOPMOST, 0, 0, 0, 0, [WinApi]::SWP_SHOWWINDOW -bor [WinApi]::SWP_NOMOVE -bor [WinApi]::SWP_NOSIZE)
    Write-Host "Window activated and set to top-most"
} else {
    Write-Host "Window not found!"
}
