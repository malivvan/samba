# Windows concurrent multi-stream read and write throughput.
# Usage: .\win-multistream.ps1 -Server fileserver -Share data [-Reads 4] [-Writes 4]
param(
    [Parameter(Mandatory=$true)][string]$Server,
    [string]$Share = "data",
    [int]$Reads = 4,
    [int]$Writes = 4
)
$unc = "\\$Server\$Share"
$sw = [System.Diagnostics.Stopwatch]::StartNew()

$jobs = @()
for ($i = 0; $i -lt $Reads; $i++) {
    $jobs += Start-Job -ScriptBlock {
        param($p)
        $fs = [System.IO.File]::OpenRead($p)
        $buf = New-Object byte[] (1MB)
        $total = 0
        while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) { $total += $n }
        $fs.Close()
        $total
    } -ArgumentList (Join-Path $unc "big.bin")
}
for ($i = 0; $i -lt $Writes; $i++) {
    $jobs += Start-Job -ScriptBlock {
        param($p)
        $buf = New-Object byte[] (1MB)
        (New-Object Random).NextBytes($buf)
        $fs = [System.IO.File]::Create($p)
        for ($j = 0; $j -lt 256; $j++) { $fs.Write($buf, 0, $buf.Length) }
        $fs.Close()
        256MB
    } -ArgumentList (Join-Path $unc "multi-$i.bin")
}
$total = ($jobs | Wait-Job | Receive-Job | Measure-Object -Sum).Sum
$jobs | Remove-Job
$sw.Stop()
$secs = $sw.Elapsed.TotalSeconds
Write-Host ("{0} streams, {1:N0} bytes in {2:N2}s = {3:N0} MB/s aggregate" -f ($Reads+$Writes), $total, $secs, ($total / 1MB / $secs))
Remove-Item (Join-Path $unc "multi-*.bin") -Force
