$shell = New-Object -ComObject Shell.Application
$shell.ShellExecute("D:\BitNet\bitnet\BitNet.Wpf\bin\Debug\net9.0-windows\BitNet.Wpf.exe", "", "", "open", 1)
Write-Host "Launched via ShellExecute"
Start-Sleep -Seconds 3
$p = Get-Process BitNet.Wpf -ErrorAction SilentlyContinue | Select-Object -First 1
if ($p) {
    Write-Host "PID: $($p.Id), HWND: $($p.MainWindowHandle), Title: $($p.MainWindowTitle), Responding: $($p.Responding)"
} else {
    Write-Host "Process not found"
}
