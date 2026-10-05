# Windows .NET FileStream streamed read throughput.
# Usage: .\win-read.ps1 -Server fileserver -Share data -File big.bin
param(
    [Parameter(Mandatory=$true)][string]$Server,
    [string]$Share = "data",
    [string]$File = "big.bin"
)
$unc = "\\$Server\$Share\$File"
$fs = [System.IO.File]::OpenRead($unc)
$buf = New-Object byte[] (1MB)
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$total = 0
while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) { $total += $n }
$sw.Stop()
$fs.Close()
$secs = $sw.Elapsed.TotalSeconds
Write-Host ("read {0:N0} bytes in {1:N2}s = {2:N0} MB/s" -f $total, $secs, ($total / 1MB / $secs))
