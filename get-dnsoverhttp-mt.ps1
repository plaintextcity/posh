<#
.SYNOPSIS
  resolve-dnsnameoverhttp
  # new-alias doh resolve-dnsnameoverhttp
  resolve dns query using Cloudflare or Google DNS over HTTPS interface
.AUTHOR
  Brian Howson April 2018 (+credits)
.DESCRIPTION

https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/

https://developers.google.com/speed/public-dns/docs/dns-over-https

https://datatracker.ietf.org/doc/draft-hoffman-dns-in-json/

https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6

https://github.com/curl/curl/wiki/DNS-over-HTTPS

# Multithreaded trickery ( refactored but list.add vs +=, foreach vs. where-object)
    http://www.get-blog.com/?p=189

TODO: make posh6 portable, enforcing Tls12 on linux
    https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod?view=powershell-5.0
# Connection limit incease trickery from
    https://social.technet.microsoft.com/wiki/contents/articles/29863.powershell-rest-api-invoke-restmethod-gotcha.aspx

# Check my encoding
   https://www.reddit.com/r/PowerShell/comments/4k77mo/encoding_spaces_for_invokerestmethod/

# DNS performance (DNS over UDP)
    https://medium.com/@nykolas.z/dns-resolvers-performance-compared-cloudflare-x-google-x-quad9-x-opendns-149e803734e5

#
    https://github.com/PowerShell/PowerShell-Docs/issues/1753


# Server Mode Garbage collection.
-- C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe.config --
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
    <runtime>
        <gcServer enabled="true"/>
        <Thread_UseAllCpuGroups enabled="true"/>
        <GCCpuGroup enabled="true"/>
    </runtime>
</configuration>

# Ephemeral port exhaustion
http://www.computertechblog.com/detecting-ephemeral-port-exhaustion-in-windows-7-8-2012/

# test cases:
    https://httpbin.org/

# Comparison with resolve-dnsname

UNKNOWN, A_AAAA, A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL, WKS, PTR, HINFO, MINFO, MX, TXT, RP, AFSDB, X25, ISDN, RT, AAAA,
SRV, DNAME, OPT, DS, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM, ANY, ALL, WINS"

# Generic list vs. recreating array to add
   https://stackoverflow.com/questions/14620290/powershell-array-add-vs
# refactored job dispatch loop, switched where-object to foreach

.Example
    resolve-dnsnameoverhttp report-uri.com
    resolve-dnsnameoverhttp report-uri.com CAA

    # work like dig -x 104.107.41.53 to get a PTR lookup 53.41.107.104.in-addr.arpa.
    resolve-dnsnameoverhttp 104.107.41.53 X

#>
function resolve-dnsnameoverhttp {
[CmdletBinding()]
param (
  [parameter(ValueFromPipeline,Position=0,Mandatory=$true)]
  [String]$Name,
  [parameter(ValueFromPipeline,Position=1,Mandatory=$false)]
  [ValidateSet("ANY","X","A","AAAA","AFSDB","APL","CAA","CDNSKEY","CDS","CERT","CNAME","DHCID","DLV","DNAME","DNSKEY","DS","HIP","IPSECKEY","KEY","KX","LOC","MX","NAPTR","NS","NSEC","NSEC3","NSEC3PARAM","OPENPGPKEY","PTR","RP","RRSIG","SIG","SOA","SRV","SSHFP","TA","TKEY","TLSA","TSIG","TXT","URI")]
  [String]$Type = "A",
  [string]$Subnet,
  [switch]$DnssecCd,
  [switch]$Google,
  [switch]$Progress,
  [switch]$Showall,
  $MaxThreads = 20,    # 20 default, for dns many more
  $SleepTimer = 200,   # 200ms default, for dns much less
  $MaxResultTime = 120 # seconds
)
BEGIN {
    $ElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()
    $CurrentSSL = [System.Net.ServicePointManager]::SecurityProtocol
    [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressSaved = $global:ProgressPreference
    if (-not $Progress) {
        $global:progressPreference = 'silentlyContinue'
    }
    if ($Google -or $DnssecCd -or $Subnet -or $Type -eq "ANY") {
        write-verbose "Using Google"
        $uri = "https://dns.google.com/resolve?"
        if ($DnssecCd) {
            $uri += "cd=1&"
        }
        if ($Subnet) {
            $uri += "edns_client_subnet=$Subnet&"
        } else {
            $uri += "edns_client_subnet=0.0.0.0/0&"
        }
        $servicePoint = [System.Net.ServicePointManager]::FindServicePoint("https://dns.google.com")
    } else {
        write-verbose "Using Cloudflare"
        $uri = "https://cloudflare-dns.com/dns-query?ct=application/dns-json&"
        $servicePoint = [System.Net.ServicePointManager]::FindServicePoint("https://cloudflare-dns.com")
    }

    $ServicePoint.ConnectionLimit = ($MaxThreads * 2)
    $global:Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $null = invoke-RestMethod -Uri ($uri + "name=google.com&type=A") -UseBasicParsing -headers $headers -UserAgent "" -TimeoutSec 20 -SessionVariable Session

    $scriptblock = {
        param (
            [Parameter(mandatory=$false, Position=0)][string]$uri,
            [Parameter(mandatory=$false, Position=1)][string]$hostname,
            [Parameter(mandatory=$false, Position=2)][switch]$Showall
        )
        $request = [System.Net.WebRequest]::Create($uri)
        $request.Method="Get"
        try {
            $response = $request.GetResponse()
        }
        catch [System.Net.WebException]
        {
            $result = $_.Exception.Response
            $result
        }
        $rvalue = $response.StatusCode.value__
        if ($rvalue -ne 200 ) {
            $response.StatusCode
        }
        $requestStream = $response.GetResponseStream()
        $readStream = New-Object System.IO.StreamReader $requestStream
        $data = $readStream.ReadToEnd()
        $results = $data | ConvertFrom-Json
        if ($results.answer) {
            $results.answer
        } elseif ($showall) {
            [PSCustomObject]@{
                name = $hostname
                type = 0
                TTL = 0
                data = $null
            }
        }
    }

    $InitialSessionState = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $InitialSessionState, $Host)
    $RunspacePool.Open()
    $OFS = "`r`n"    # Output Field Separator
    $Code = [ScriptBlock]::Create($scriptblock)
    Remove-Variable OFS
    $Jobs = New-Object System.Collections.Generic.List[System.Object]
}
PROCESS {
#    if ($Type -eq "X" -and $Name -match "^(([01]?[0-9]?[0-9]|2[0-5][0-5])\.){3}([01]?[0-9]?[0-9]|2[0-5][0-5])$") {
    if ($Type -eq "X" -and $Name -match "^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.(?!$)|$)){4}$") {
        $IP = $Name.split(".")
        $Name = $IP[3] + "." +  $IP[2] + "." + $IP[1] + "." + $IP[0] + ".in-addr.arpa."
        $xType = "PTR"
    } else {
        $xType = $Type
    }
    ForEach ($nm in $Name){
        $quri = $uri + "name=$nm&type=$xType"
        write-verbose "$quri"
        if ($Progress) {
            Write-Progress -Activity "Preloading threads" -Status "Starting Job $($jobs.count) $Name"
        }
        $PowershellThread = [powershell]::Create().AddScript($Code)
        $null = $PowershellThread.AddParameter("uri",$quri)
        $null = $PowershellThread.AddParameter("hostname",$nm)
        $null = $PowershellThread.AddParameter("showall",$showall)
        $PowershellThread.RunspacePool = $RunspacePool
        $Handle = $PowershellThread.BeginInvoke()

        $Job = "" | Select-Object Handle, Thread, object
        $Job.Handle = $Handle
        $Job.Thread = $PowershellThread
        $Job.Object = $Name
        $Jobs.Add($Job)
    }
}
End {
    $Remaining = 1
#    $maxrun = $($MaxThreads - $($RunspacePool.GetAvailableRunspaces()))
    While ($Remaining -gt 0)  {
        $Remaining = 0
        ForEach ($Job in $Jobs) {
            if ($Job.Handle.IsCompleted -eq $True) {
                $Job.Thread.EndInvoke($Job.Handle)
                $Job.Thread.Dispose()
                $Job.Thread = $Null
                $Job.Handle = $Null
            } elseif ((-not $running) -and ($Null -ne $Job.Handle)) {
                $Remaining += 1
            }
        }
        if ($Progress) {
            Write-Progress `
                -Activity "Waiting for Jobs - $($MaxThreads - $($RunspacePool.GetAvailableRunspaces())) of $MaxThreads threads running" `
                -PercentComplete (($Jobs.Count - $Remaining)/ $Jobs.Count * 100)`
                -Status "Remaining $Remaining"
        }
        Start-Sleep -Milliseconds $SleepTimer
    }
    $null = $RunspacePool.Close()
    $null = $RunspacePool.Dispose()
    $null = $ServicePoint.CloseConnectionGroup("")
    [System.Net.ServicePointManager]::SecurityProtocol = $CurrentSSL
    $global:ProgressPreference = $ProgressSaved
    write-verbose "Elapsed Time: $($ElapsedTime.Elapsed.ToString())"
    write-host "Elapsed Time: $($ElapsedTime.Elapsed.ToString())"
    remove-variable Session 
}
}
