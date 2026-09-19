# Read current clipboard text and format list from an external process.
# Note: keep this file ASCII-only. Windows PowerShell 5.1 parses .ps1 files
# without a BOM as ANSI, which corrupts non-ASCII characters.
# Run with: powershell.exe -NoProfile -File tools\read_clipboard.ps1
Add-Type -AssemblyName System.Windows.Forms

$data = $null
for ($i = 0; $i -lt 12; $i++) {
    try {
        $data = [System.Windows.Forms.Clipboard]::GetDataObject()
        break
    } catch {
        Start-Sleep -Milliseconds 250
    }
}

if ($null -eq $data) {
    Write-Host "CLIPBOARD: <locked or empty>"
} else {
    Write-Host ("TEXT: " + $data.GetData('Text'))
    Write-Host ("FORMATS: " + ($data.GetFormats() -join ", "))
}
