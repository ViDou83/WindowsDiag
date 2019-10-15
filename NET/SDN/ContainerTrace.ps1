param(
    [Parameter(Mandatory = $false)] [Boolean]$IncludeNetworkTrace = $true,
    [Parameter(Mandatory = $false)] [Boolean]$CollectGetNetView = $true,
    [Parameter(Mandatory = $false)] [string]$traceFile = "C:\$($env:COMPUTERNAME)_ContainerTrace.etl",
    [Parameter(Mandatory = $false)] [string]$MaxTraceSize = 1024,
    [Parameter(Mandatory = $false)] [Boolean]$Multilayer = $false,
    [Parameter(Mandatory = $false)] [Boolean]$IncludeHNSiDNA = $false,
    [Parameter(Mandatory = $false)] [String]$ProcessToiDNATrace = "hns",
    [Parameter(Mandatory = $false)] [String]  $IdnaPath

)

# the primary WNV ETW provider.
[array]$providerList = @( 
    '{67DC0D66-3695-47C0-9642-33F76F7BD7AD}', #Microsoft-Windows-Hyper-V-VmSwitch	
    '{1F387CBC-6818-4530-9DB6-5F1058CD7E86}', #Microsoft-Windows-Hyper-V-VmSwitch	
    '{9F2660EA-CFE7-428F-9850-AECA612619B0}', #Microsoft-Windows-Hyper-V-VfpExt	
    '{B72C6994-9FE0-45AD-83B3-8F5885F20E0E}', #Microsoft-Windows-MsLbfoEventProvider
    '{66C07ECD-6667-43FC-93F8-05CF07F446EC}', #Microsoft-Windows-WinNat	
    '{0C885E0D-6EB6-476C-A048-2457EED3A5C1}', #Microsoft-Windows-Host-Network-Service	
    '{0BACF1D2-FB51-549A-6119-04DAA7180DC8}', #Microsoft-Windows-Guest-Network-Service		
    '{9D911DDB-D45F-41C3-B766-D566D2655C4A}', #containermanager
    '{662abf07-6dda-5b25-c2c5-345236dbb2d2}', #FSE
    '{A111F1C0-5923-47C0-9A68-D0BAFB577901}', #Microsoft.Windows.Networking.NetworkSetup	
    '{EB004A05-9B1A-11D4-9123-0050047759BC}', #NETIO
    '{0C478C5B-0351-41B1-8C58-4A6737DA32E3}', #Microsoft-Windows-WFP
    '{564368D6-577B-4af5-AD84-1C54464848E6}', #Overlay Pluging Tracer
    '{80CE50DE-D264-4581-950D-ABADEEE0D340}', #compute (container)
    '{D0E4BC17-34C7-43fc-9A72-D89A59D6979A}', #Microsoft.Windows.HostNetworkingService.PrivateCloudPlugin
    '{93f693dc-9163-4dee-af64-d855218af242}', #netmgmt
    '{A6F32731-9A38-4159-A220-3D9B7FC5FE5D}'  #Microsoft-Windows-SharedAccess_NAT
)

$Disclaimer = 
'*****************************************************************************************************************************
    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
    WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN 
    AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
    DEALINGS IN THE SOFTWARE. 
*****************************************************************************************************************************
'
Write-Host $Disclaimer -ForegroundColor Yellow

# press a key to stop

do {
    Write-Host "`n`n Please type y/Y if you want to execute this script or n/N if you don't !" -ForegroundColor Green
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
} until ($x.Character -eq 'y' -or $x.Character -eq 'Y' -or $x.Character -eq 'n' -or $x.Character -eq 'N')

if ( $x.Character -eq 'n' -or $x.Character -eq 'N') {
    Write-Host "INFO: Exiting $PROGRAMNAME as user requested" -ForegroundColor Yellow
    exit 1
}

if ( $IncludeHNSiDNA) {
    if ( test-path $env:windir\System32\tttracer.exe ) {
        Write-Host -ForegroundColor Yellow "Creating iDNA trace of HNSService"                
        #TTD EULA
        if ( -Not ( Test-Path 'HKCU:\.DEFAULT\Software\Microsoft\TTD' ) ) {
            New-Item -PAth 'HKCU:\.DEFAULT\Software\Microsoft\TTD' -Force | Out-Null
        }

        if ( -Not ( Test-Path 'HKCU:\.DEFAULT\Software\Microsoft\TTT' ) ) {
            New-Item -PAth 'HKCU:\.DEFAULT\Software\Microsoft\TTT' -Force | Out-Null
        }
    
        if ( Test-Path 'HKCU:\.DEFAULT\Software\Microsoft\TTD' ) {
            New-ItemProperty -PAth 'HKCU:\.DEFAULT\Software\Microsoft\TTD' -Name EULASigned -Value 1 `
                -PropertyType DWORD -Force | Out-Null   
        }

        if ( Test-Path 'HKCU:\.DEFAULT\Software\Microsoft\TTT' ) {
            New-ItemProperty -PAth 'HKCU:\.DEFAULT\Software\Microsoft\TTT' -Name EULASigned -Value 1 `
                -PropertyType DWORD -Force | Out-Null    
        }

        #TTD inbox recorder is only available on Win10 RS5 devices with x86 or x64 architecture for OneCoreUAP and higher editions.
        if ( [System.Environment]::OSVersion.Version.Major -eq 10 -and [System.Environment]::OSVersion.Version.Build -ge 17763 ) {
            if ( $IdnaPath ) {
                Write-Host "INFO: native TTTracer will be used instead of the located one under $IdnaPath " -ForegroundColor Yellow
            } 
            $IdnaExe = "$env:windir\system32\tttracer.exe"
        }

        #Get HNS PID
        $res = tasklist /Svc /FO CSV | findstr $ProcessToiDNATrace
        if ( $res ) { 
            $PidToIdna = $res.split(",")[1].replace('"', '')
            Write-Host -ForegroundColor Yellow "IDNA: Starting trace of HNS PID=$PidToIdna in background" 
            $null = start-job -ScriptBlock { param($IdnaExe, $PidToIdna, $ProcessToiDNATrace) "$IdnaExe -attach $PidToIdna -noUI -out $env:SystemDrive\$ProcessToiDNATrace%.run" | cmd } -Arg $IdnaExe, $PidToIdna, $ProcessToiDNATrace
        }
        else { throw "HNS service is not running. Please fix this issue and then rerun this script!" }
    }
    else { throw "TTTracer not present so please don't try to collect IDNA trace from this script!" }
}

# create the capture session
Write-Host -ForegroundColor Yellow "Creating NetEventSession on $env:COMPUTERNAME"
New-NetEventSession -Name Container_Trace -LocalFilePath $traceFile -MaxFileSize 1024 
            
# add the packet capture provider
if ( $IncludeNetworkTrace) { 
    Write-Host -ForegroundColor Yellow "Collecting Network Trace"
    Add-NetEventPacketCaptureProvider -SessionName Container_Trace -MultiLayer $Multilayer 
}

# add providers to the trace
Write-Host -ForegroundColor Yellow "Adding HNS/NAT/VMSWITCH ETW provider"
foreach ($provider in $providerList) {
    Write-Host "Adding provider $provider"
    try {
        Add-NetEventProvider -SessionName Container_Trace -Name $provider -Level $([byte]0x6) -EA Stop | Out-NUll
    }
    catch {
        Write-Host "Could not add provider $provider"
    }
}

Start-NetEventSession Container_Trace 

# press a key to stop
Write-Host -ForegroundColor Green "`n`nReproduce the issue then press the 's' key to stop tracing."

do {
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
} until ($x.Character -eq 's' -or $x.Character -eq 'S')

Write-Host -ForegroundColor yellow "Stopping Net and ETL trace."

#Stopping iDNA if needed
if ( $IncludeHNSiDNA) {
    Write-Host -ForegroundColor Yellow "Stopping iDNA trace PID=$PidToIdna"
    Invoke-Expression "$IdnaExe -stop $PidToIdna" 
}

# stop the trace
Stop-NetEventSession Container_Trace  
Remove-NetEventSession Container_Trace  

#see https://github.com/microsoft/Get-NetView
if ($CollectGetNetView) {
    Install-Module Get-NetView
    Get-NetView
}

Write-Host -ForegroundColor Yellow "Container trace is available at $traceFile"
$IdnaTrace = ((get-item  C:\HNS*.run).fullName)[-1]
Write-Host -ForegroundColor Yellow "iDNA trace is available at $IdnaTrace"

