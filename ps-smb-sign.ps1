# USAGE: 
# 1. Create a file named "computers.txt" in the same folder (IPs or Hostnames).
# 2. Run this script as Administrator (Domain Admin credentials recommended).
# 3. Output saved to "SMB_Signing_Report.csv".

$inputFile = ".\computers.txt"
$outputFile = ".\SMB_Signing_Report.csv"
$results = @()

# Check input file
if (-not (Test-Path $inputFile)) {
    Write-Host "Error: '$inputFile' not found." -ForegroundColor Red; exit
}

$targets = Get-Content -Path $inputFile
Write-Host "Scanning $($targets.Count) targets..." -ForegroundColor Cyan

foreach ($inputItem in $targets) {
    $inputItem = $inputItem.Trim()
    if ([string]::IsNullOrWhiteSpace($inputItem)) { continue }

    # Initialize variables
    $resolvedHostname = $null
    $resolvedIP = $null
    $targetForCommand = $inputItem # Default to input if resolution fails
    $status = "Unknown"
    $notes = ""

    # --- Step 1: DNS Resolution ---
    # We try to resolve IPs to Hostnames because WinRM prefers Hostnames.
    try {
        $dnsEntry = [System.Net.Dns]::GetHostEntry($inputItem)
        $resolvedHostname = $dnsEntry.HostName
        $resolvedIP = $dnsEntry.AddressList | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1 -ExpandProperty IPAddressToString
        
        # If the input was an IP, we switch the target to the Hostname for better connection success
        if ($inputItem -match "^\d{1,3}\.") {
            $targetForCommand = $resolvedHostname
        }
    }
    catch {
        $notes = "DNS Resolution Failed. "
        $resolvedHostname = "Unknown"
        $resolvedIP = $inputItem 
    }

    # --- Step 2: Check SMB Configuration ---
    try {
        # Check specific registry key if WinRM fails, but start with CimSession (standard)
        # Using -ErrorAction Stop to catch connection issues
        $smbConfig = Get-SmbServerConfiguration -CimSession $targetForCommand -ErrorAction Stop
        
        if ($smbConfig.RequireSecuritySignature -eq $false) {
            $status = "VULNERABLE"
            Write-Host "[!] $targetForCommand ($resolvedIP) is VULNERABLE" -ForegroundColor Yellow
        } else {
            $status = "SECURE"
            Write-Host "[+] $targetForCommand ($resolvedIP) is Secure" -ForegroundColor Green
        }
    }
    catch {
        $status = "ERROR"
        $notes += "Connection Failed: $($_.Exception.Message)"
        Write-Host "[-] Could not connect to $inputItem" -ForegroundColor Red
    }

    # Add to results list
    $results += [PSCustomObject]@{
        InputProvided = $inputItem
        Hostname      = $resolvedHostname
        IPAddress     = $resolvedIP
        SigningStatus = $status
        Notes         = $notes
    }
}

# --- Step 3: Export ---
$results | Export-Csv -Path $outputFile -NoTypeInformation
Write-Host "`nDone! Report saved to $outputFile" -ForegroundColor Cyan
