
# USAGE: 
# 1. Create a "computers.txt" file with IPs or Hostnames (one per line).
# 2. Run: PowerShell.exe -ExecutionPolicy Bypass -File .\Check-SmbSigning-Universal.ps1
# 3. This works on WINDOWS and LINUX (Samba) targets.

$inputFile = ".\computers.txt"
$outputFile = ".\Vulnerable_Hosts.csv"
$results = @()

if (-not (Test-Path $inputFile)) { Write-Host "Error: computers.txt not found." -ForegroundColor Red; exit }

$targets = Get-Content -Path $inputFile
Write-Host "Scanning $($targets.Count) targets on Port 445..." -ForegroundColor Cyan

foreach ($hostTarget in $targets) {
    $hostTarget = $hostTarget.Trim()
    if ([string]::IsNullOrWhiteSpace($hostTarget)) { continue }

    $status = "Unknown"
    $details = ""
    $isVulnerable = $false

    try {
        # 1. Connect to TCP Port 445
        $socket = New-Object System.Net.Sockets.TcpClient
        $connectTask = $socket.ConnectAsync($hostTarget, 445)
        if (-not $connectTask.Wait(1000)) { # 1 second timeout
             throw "Connection Timeout" 
        }

        $stream = $socket.GetStream()

        # 2. Construct SMB2 Negotiate Packet (The "Hello")
        # Packet Structure: [NetBIOS Header (4)] + [SMB2 Header (64)] + [Negotiate Body (36)] + [Dialects (4)] = 108 bytes
        
        $packet = [byte[]]::new(108)
        
        # NetBIOS Session Service Header (Length = 104 bytes for the SMB data)
        $packet[0] = 0x00
        $packet[1] = 0x00
        $packet[2] = 0x00
        $packet[3] = 0x68 # 104 decimal

        # SMB2 Header ProtocolID (\xfeSMB)
        $packet[4] = 0xFE; $packet[5] = 0x53; $packet[6] = 0x4D; $packet[7] = 0x42
        $packet[8] = 0x40 # StructureSize (64)
        $packet[16] = 0x00 # Command (Negotiate = 0)
        
        # Negotiate Request Body
        $packet[68] = 0x24 # StructureSize (36)
        $packet[70] = 0x02 # DialectCount (2)
        $packet[72] = 0x01 # SecurityMode (Signing Enabled by client)
        
        # Dialects (SMB 2.0.2 and SMB 2.1)
        $packet[104] = 0x02; $packet[105] = 0x02
        $packet[106] = 0x10; $packet[107] = 0x02

        # 3. Send Packet
        $stream.Write($packet, 0, $packet.Length)

        # 4. Read Response
        $buffer = [byte[]]::new(1024)
        $bytesRead = $stream.Read($buffer, 0, $buffer.Length)

        if ($bytesRead -gt 68) {
            # Parse SMB2 Response
            # The SecurityMode field is at Offset 2 inside the Negotiate Response Body.
            # Header is 64 bytes. Body starts at index 64 (excluding NetBIOS header of 4 bytes).
            # So looking at Buffer index: 4 (NetBIOS) + 64 (SMB Header) + 2 (Offset) = 70.
            
            $serverSecurityMode = $buffer[74] # 4 (NetBIOS) + 64 (Header) + 2 (StructureSize) + 2 (SecurityMode offset is actually 2) = 72?
            # Wait, let's recount carefully.
            # Response Packet: [NetBIOS (4)] [SMB Header (64)] [Negotiate Body]
            # Negotiate Body Byte 0-1: StructureSize
            # Negotiate Body Byte 2-3: SecurityMode
            # Index = 4 + 64 + 2 = 70.
            
            $securityMode = $buffer[70]

            # Bit 0 (1): Signing Enabled
            # Bit 1 (2): Signing Required
            
            $signingEnabled = ($securityMode -band 1) -eq 1
            $signingRequired = ($securityMode -band 2) -eq 2

            if (-not $signingRequired) {
                $status = "VULNERABLE"
                $details = "Signing Enabled: $signingEnabled, Required: FALSE"
                Write-Host "[-] $hostTarget : VULNERABLE (Signing Not Required)" -ForegroundColor Yellow
                $isVulnerable = $true
            } else {
                $status = "SECURE"
                $details = "Signing Required: TRUE"
                Write-Host "[+] $hostTarget : Secure" -ForegroundColor Green
            }
        } else {
            $status = "Error"
            $details = "Invalid Response Length"
            Write-Host "[!] $hostTarget : Invalid Response" -ForegroundColor Red
        }

        $socket.Close()
    }
    catch {
        $status = "Unreachable"
        $details = $_.Exception.Message
        Write-Host "[x] $hostTarget : Connection Failed" -ForegroundColor DarkGray
    }

    # Only export vulnerable hosts (or all if you prefer, currently setup for all)
    if ($isVulnerable) {
        $results += [PSCustomObject]@{
            Host = $hostTarget
            Status = $status
            Details = $details
        }
    }
}

$results | Export-Csv -Path $outputFile -NoTypeInformation
Write-Host "`nScan Complete. Found $($results.Count) vulnerable systems." -ForegroundColor Cyan
