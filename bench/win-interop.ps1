# Windows SMB client interop check: connect, list, read, write, and report the
# negotiated dialect and signing state.
# Usage:  .\win-interop.ps1 -Server fileserver -Share data -User alice -Password secret
param(
    [Parameter(Mandatory=$true)][string]$Server,
    [string]$Share = "data",
    [string]$User = "",
    [string]$Password = ""
)
$ErrorActionPreference = "Stop"
$unc = "\\$Server\$Share"

Write-Host "== connect =="
if ($User) { net use $unc /user:$User $Password } else { net use $unc }
Get-SmbConnection -ServerName $Server | Select-Object ServerName,Dialect,Signed,Encrypted | Format-List

Write-Host "== list =="
Get-ChildItem $unc | Select-Object -First 10 Name,Length

Write-Host "== write =="
$src = Join-Path $env:TEMP "samba-src.bin"
$fs = [System.IO.File]::Create($src)
$buf = New-Object byte[] (1MB)
(New-Object Random).NextBytes($buf)
for ($i = 0; $i -lt 64; $i++) { $fs.Write($buf, 0, $buf.Length) }
$fs.Close()
Copy-Item $src (Join-Path $unc "interop.bin") -Force

Write-Host "== read back =="
$dst = Join-Path $env:TEMP "samba-dst.bin"
Copy-Item (Join-Path $unc "interop.bin") $dst -Force
$a = (Get-FileHash $src -Algorithm MD5).Hash
$b = (Get-FileHash $dst -Algorithm MD5).Hash
if ($a -ne $b) { Write-Error "MD5 MISMATCH: $a != $b" }
Write-Host "  md5 OK ($a)"

Remove-Item (Join-Path $unc "interop.bin") -Force
net use $unc /delete | Out-Null
Write-Host "PASS"
