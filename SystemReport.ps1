#requires -Version 3.0 -Modules International, Microsoft.PowerShell.Diagnostics, Microsoft.PowerShell.Utility, NetTCPIP, PowerShellGet, PSWriteHTML, DotNetVersionLister
#PowerShellGet Source: https://www.powershellgallery.com/api/v2
#PSWriteHTML Source: https://www.powershellgallery.com/api/v2
#DotNetVersionLister Source: https://www.powershellgallery.com/packages/DotNetVersionLister/3.0.1

$ErrorAction = 'SilentlyContinue'
Clear-Host

<#param
    (
    [parameter(
      Mandatory=$false
    )]
    [switch]$outputHTML
    )
#>

#If current execution policy isn't high enough for this script self elevate
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
  Write-Verbose -Message "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
  Start-Process -FilePath powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
  Exit
}

#Set Error action to silent and continue to prevent errors from presenting to the user and stopping the script. Error handling must be manually captured and added to the error list object for display on a report tab
$ErrorActionPreference = $ErrorAction
$DebugPreference = $ErrorAction

#Create new object list to hold all collected error objects to pass to report at the end 
$errList = New-Object -TypeName System.Collections.Generic.List[System.Object]

#Function to build object containing caught error information that gets added to a list for output as a report tab
function Get-ErrorObject
{
  return [object[]]$($Error | Select-Object -First 1 -Property @{
      n = 'ErrorType'
      e = { $_.Exception.ErrorRecord.FullyQualifiedErrorId }
    }, @{
      n = 'Message'
      e = { $_.Exception.Message }
    }, @{
      n = 'Value' 
      e = { $_.Exception.ErrorRecord.CategoryInfo.TargetName }
    }, @{
      n = 'ValueType'
      e = { $_.Exception.ErrorRecord.CategoryInfo.TargetType }
    }, @{
      n = 'StackTrace'
      e = { ("{0}`r`n{1}" -f $_.Exception.StackTrace, $_.Exception.ErrorRecord.ScriptStackTrace) }      
  })
}

#Ensure the file is unblocked if it was downloaded from the internet or saved from email
try 
{
  Unblock-File -Path $PSCommandPath 
}
catch
{
  $errList += (Get-ErrorObject)
}

#Load a list of percentages per line for progress feedback
$percs = @{}
$lines = Get-Content -Path $MyInvocation.InvocationName 
$totLines = $lines.Count
for ($x = 0; $x -lt $totLines; $x += 1) 
{
  $perc = ($x/$totLines) * 100
  $percs.Add($x, $perc)
}
function Get-CurrentLineNumber 
{
  Return [int]$MyInvocation.ScriptLineNumber
}

Write-Progress -Activity 'Compatibility checks' -Status '...' -CurrentOperation 'Checking for required dependencies, if this is the first time this script is run on this computer attempts will be made to install dependencies where necessary...' -PercentComplete ($percs[(Get-CurrentLineNumber)])

#region Load dependencies
try
{
  $null = [Reflection.Assembly]::LoadWithPartialName('Microsoft.Powershell.Utility')
  $null = [Reflection.Assembly]::LoadWithPartialName('Windows.System.Media')
  $null = [Reflection.Assembly]::LoadWithPartialName('Windows.UI.Colors')

  if (!(Get-Module -ListAvailable -Name PowerShellGet))
  {
    Write-Progress -Activity 'Compatibility checks' -CurrentOperation 'Installing PowerShellGet module... ' -PercentComplete ($percs[(Get-CurrentLineNumber)])
    $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted 
    $null = Install-Module -Name PowerShellGet -MinimumVersion 2.2.0.0 -Repository PSGallery -SkipPublisherCheck
  }

  if (!(Get-Module -ListAvailable -Name PSWriteHTML))
  {
    Write-Progress -Activity 'Compatibility checks' -CurrentOperation 'Installing PSWriteHTML module... ' -PercentComplete ($percs[(Get-CurrentLineNumber)])
    $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted 
    $null = Install-Module -Name PSWriteHTML -MinimumVersion 0.0.39 -Repository PSGallery -SkipPublisherCheck
    $null = Install-Module -Name PSSharedGoods -Repository PSGallery -SkipPublisherCheck
  }
  
  if (!(Get-Module -ListAvailable -Name DotNetVersionLister))
  {
    Write-Progress -Activity 'Compatibility checks' -CurrentOperation 'Installing PSWriteHTML module... ' -PercentComplete ($percs[(Get-CurrentLineNumber)])
    $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted 
    $null = Install-Module -Name DotNetVersionLister -Repository PSGallery -SkipPublisherCheck
  }  

  $null = Import-Module -Name PSWriteHTML -Force
  $null = Import-Module -Name PSSharedGoods -Force
  $null = Import-Module -Name DotNetVersionLister -Force
}
catch
{
  
}
#endregion

$MainProgressMsgText = 'Running System Report'
Write-Progress -Activity $MainProgressMsgText -CurrentOperation 'Initialise variables and lists...' -PercentComplete ($percs[(Get-CurrentLineNumber)])

#region Assign\Initialise Variables

$LocalHostText = 'localhost'
$statcolGreen = 'Green'
$statcolOrange = 'Orange'
$statcolBlue = 'Blue'
$computer = 'LocalHost' 
$namespace = 'root\CIMV2' 

$indicatorIconSet = @{
  'Blue' = 'info'
  'Orange' = 'exclamation'
  'Green' = 'check'
}

$statusColors = @{
  'ok'    = $statcolGreen
  'good'  = $statcolGreen
  'warning' = $statcolOrange
  'warn'  = $statcolOrange
  'fail'  = $statcolOrange
  'bad'   = $statcolOrange
}

$procAvailability = @{
  1 = 'Other'
  2 = 'Unknown '
  3 = 'Running Full Power'
  4 = 'Warning'
  5 = 'In Test'
  6 = 'Not Applicable'
  7 = 'Power Off'
  8 = 'Off Line'
  9 = 'Off Duty'
  10 = 'Degraded'
  11 = 'Not Installed'
  12 = 'Install Error'
  13 = 'Power Save - Unknown'
  14 = 'Power Save - Low Power Mode'
  15 = 'Power Save - Standby'
  16 = 'Power Cycle'
  17 = 'Power Save - Warning'
  18 = 'Paused'
  19 = 'Not Ready'
  20 = 'Not Configured'
  21 = 'Quiesced' 
}

$RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
$ComputerName = $LocalHostText
$detailLinkText = 'Details'
$ArrayList = 'System.Collections.ArrayList'
$backSlash = '\'
$varDash = '-'
$repLink = '' #used to get subreport links from sub report function
$totMem = ''
$freeMem = ''
$baseReportDir = "$env:TEMP\SystemReport"
$baseReportDir += ($varDash + (Get-Date -Format yyyyMMdd-HHmmss) + $backSlash)

#Create the base save directory if it doesn't exist
if (!(Test-Path -Path $baseReportDir)) 
{
  $null = New-Item -Path $baseReportDir -ItemType Directory -Force
}

 $reportSaveName = $baseReportDir + 'report.html'

<#if ($outputHTML) {
    $reportSaveName = $baseReportDir + 'report.html'
    } else
    {
    $reportSaveName = $baseReportDir + 'report.txt'
    }

#>$repCPU = New-Object -TypeName $ArrayList
$repBIOS = New-Object -TypeName $ArrayList
$repMEM = New-Object -TypeName $ArrayList
$repDisk = New-Object -TypeName $ArrayList
$repUpdates = New-Object -TypeName $ArrayList
$repDOTNET = New-Object -TypeName $ArrayList
$repSQLApps = New-Object -TypeName $ArrayList
$dataCollectionTimes = New-Object -TypeName $ArrayList
#endregion Assign Variables

#region Local Functions
Write-Progress -Activity $MainProgressMsgText -CurrentOperation 'Creating required functions and classes...' -PercentComplete ($percs[(Get-CurrentLineNumber)])
function Get-ParentProcess
{
  param
  (
    [Parameter(Mandatory = $true, HelpMessage = 'Process ID of child process for which to find the parent process')]
    [int]
    $childID
  )
  $parentprocess = [string](Get-Process -Id $childID -ErrorAction SilentlyContinue | Select-Object -Property ProcessName)  
  if ([string]::IsNullOrEmpty($parentprocess)) {
    $parentprocess = 'Not found.'  
  }
  return $parentprocess
}

function Select-EventLogIsApplication
{
  param
  (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = 'Data to filter')]
    $InputObject
  )
  process
  {
    if ($InputObject.Name -eq 'Application')
    {
      $InputObject
    }
  }
}
function Select-EventLogList
{
  $eventLogs = New-Object -TypeName System.Collections.Generic.List[System.Object]
  Get-WinEvent -ListLog * | Select-RecordsExist | Select-Object -Property * | ForEach-Object -Process {
    $eventLogs += 
    [PSCustomObject]@{
      LogMode = $_.LogMode
      Size    = $_.MaximumSizeInBytes
      Events  = $_.RecordCount
      Name    = $_.LogName
    }
  }
  return $eventLogs
}
function Select-RecordsExist
{
  param
  (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = 'Data to filter')]
    $InputObject
  )
  process
  {
    if ($InputObject.RecordCount -gt 0)
    {
      $InputObject
    }
  }
}
function Select-PortData
{
  $portList = New-Object -TypeName System.Collections.Generic.List[System.Object]
  Get-NetTCPConnection | Select-Object -Property * | ForEach-Object -Process {
    $portList += 
    [PSCustomObject]@{
      State         = $_.State
      LocalAddress  = $_.LocalAddress
      LocalPort     = $_.LocalPort
      RemoteAddress = $_.RemoteAddress
      RemotePort    = $_.RemotePort
      OwningProcess = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue | Select-Object -Property Description).Description
    }
  }
  return $portList
}

function Select-PortsByState
{
  param
  (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    $allPorts,
    [string]
    $portFilter = ''
  )
  process
  {
    if ($allPorts.State -eq $portFilter)
    {
      return $allPorts
    }
  }  
}
function Get-FieldValuesAsHTMLList
{
  param
  (
    [Parameter(Mandatory)]
    $InputObject
  )
  try
  {
    $content = '<ul style="list-style: none;">'
    ForEach ($o in $InputObject) 
    {
      $content += ('<li>{0}</li>' -f [string]$o)
    }
    $content += '</ul>'
    return $content
  }
  catch 
  {

  }
}

function Get-EventLogCustom
{
  #Content
  param
  (
    [String]
    [Parameter(Mandatory)]
    $logName
  )
  
  $logObj = New-Object -TypeName 'System.Collections.Generic.List[System.Object]'      
  try
  {
     Get-WinEvent -LogName $logName -MaxEvents 100 | Select-Object -Property * | ForEach-Object -Process {
      $logObj += 
      [PSCustomObject]@{
        Source    = $_.ProviderName
        Date      = $_.TimeCreated
        EventType = $_.LevelDisplayName
        ID        = $_.Id
        Message   = $_.Message    
     
      }
    }
  }
  catch 
  {
    $errList += (Get-ErrorObject)
  }
  return $logObj
}

function Get-CounterByName
{
  param
  (
    [String]
    [Parameter(Mandatory)]
    $counterName
  )
  
  function Select-CounterData
  {
    param
    (
      [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = 'Data to process')]
      $InputObject
    )
    process
    {
      $r = New-Object -TypeName System.Collections.Generic.List[System.Object]    
      if ([math]::Round($InputObject.CookedValue,2) -gt 0) 
      {
        $r += 
        [PSCustomObject]@{
          Counter = Cut-Path -inputString $InputObject.Path
          Value   = [math]::Round($InputObject.CookedValue,2)
        }
      }
      return $r
    }
  }

  $result = New-Object -TypeName System.Collections.Generic.List[System.Object]
  Get-Counter -Counter ((Get-Counter -ListSet $counterName).Paths) | Select-Object -ExpandProperty CounterSamples | Select-CounterData
  return $result
}

function Get-SectionDurationObject
{
  param
  (
    [Diagnostics.Stopwatch]
    [Parameter(Mandatory)]
    $tmrObject,
    [int]
    $secCount = 0,
    [string]
    $secName = ''
  )

  $result = New-Object -TypeName PSObject -Property @{
    Duration = $tmrObject.Elapsed
    Section  = $secName
    Count    = $secCount
  }
  return $result
}
function script:Make-ItALink
{
  param
  (
    [string]
    [Parameter(Mandatory = $true, HelpMessage = 'URL that the link should lead to')]
    $linkURL,
    [string]
    [Parameter(Mandatory = $true, HelpMessage = 'Link text visible on the report')]
    $linkText
  )
  $theLink = '<a href="{0}" target=_blank>{1}</a>' -f $linkURL, $linkText
  Return $theLink
}
function Get-InstalledApps 
{
  param
  (
    [Parameter(Mandatory = $true)]
    $allAppsObject,
    [string]
    $filterValue = ''
  )
  $InstalledLinksText = 'Installed'
  $UpdatesLinkText = 'Updates'
  $AboutLinkText = 'About'
  $HelpLinkText = 'Help'
  $result = New-Object -TypeName System.Collections.Generic.List[System.Object]
  if ($filterValue -ne '') 
  {
    $result = ($allAppsObject | Select-Object -Property DisplayName, DisplayVersion, InstallDate, @{
        n = $InstalledLinksText
        e = {
          if (!([string]::IsNullOrEmpty($_.InstallLocation))) {
            (Make-ItALink -linkURL $_.InstallLocation -linkText 'Open Folder') 
          }
        }
      }, Publisher, @{
        n = $HelpLinkText
        e = {
          if (!([string]::IsNullOrEmpty($_.HelpLink))) {
            (Make-ItALink -linkURL $_.HelpLink -linkText 'Help') 
          }
        }
      }, Version, @{
        n = $AboutLinkText
        e = {
          if (!([string]::IsNullOrEmpty($_.URLInfoAbout))) {
            (Make-ItALink -linkURL $_.URLInfoAbout -linkText 'About') 
          }
        }
      }, @{
        n = $UpdatesLinkText
        e = {
          if (!([string]::IsNullOrEmpty($_.URLUpdateInfo))) {
            (Make-ItALink -linkURL $_.URLUpdateInfo -linkText 'Updates') 
          }
        }
      } | Where-Object -FilterScript {
        $_.DisplayName -like ('*{0}*' -f $filterValue) 
    })
  }
  else 
  {
    $result = ($allAppsObject | Select-Object -Property DisplayName, DisplayVersion, InstallDate, @{
        n = $InstalledLinksText
        e = {
          if (!([string]::IsNullOrEmpty($_.InstallLocation))) {        
            (Make-ItALink -linkURL $_.InstallLocation -linkText 'Open Folder') 
          }
        }
      }, Publisher, @{
        n = $HelpLinkText
        e = {
          if (!([string]::IsNullOrEmpty($_.HelpLink))) { 
            (Make-ItALink -linkURL $_.HelpLink -linkText 'Help') 
          }
        }
      }, Version, @{
        n = $AboutLinkText
        e = {
          if (!([string]::IsNullOrEmpty($_.URLInfoAbout))) {
            (Make-ItALink -linkURL $_.URLInfoAbout -linkText 'About') 
          }
        }
      }, @{
        n = $UpdatesLinkText
        e = {
          if (!([string]::IsNullOrEmpty($_.URLUpdateInfo))) {
            (Make-ItALink -linkURL $_.URLUpdateInfo -linkText 'Updates') 
          }
        }
    })
  }
  return $result
}
function Get-ServiceByStatus
{
  param
  (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = 'Object to filter')]
    $allServices, 
    [string]
    $serviceFilter = '',
    [string]
    $filterField = 'Status'
  )
  process
  {
    if ($allServices.$filterField -eq $serviceFilter)
    {
      return $allServices | Select-Object -Property DisplayName, Name, Status, StartType | Sort-Object -Property DisplayName 
    }
  }  
}
function Get-ServiceBadState
{
  param
  (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = 'Data to filter')]
    $InputObject
  )
  process
  {
    if ($InputObject.StartType -eq 'Automatic' -and $InputObject.Status -ne 'Running')
    {
      $InputObject
    }
  }
}
function Get-SectionStatus
{
  param
  (
    [string]
    [Parameter(Mandatory = $true, HelpMessage = 'String that contains a status indicator. E.g. OK, Good, Poor, Bad etc...')]
    $statusText,
    [double]
    $statusThresholdValue = 0.00,
    [string]
    [Parameter(Mandatory = $true, HelpMessage = 'Alpha type e.g. "OK" or Numeric type e.g. 55')]
    $statusType
  )

  $statusColor = $statcolBlue
  try
  {
    if ($statusType -eq 'Alpha') 
    {
      #First find the status keyword then resolve the color
      $searchArr = $statusText.Split(' ')
      foreach ($word in $searchArr) 
      {
        if ($statusColors.ContainsKey($word)) 
        { 
          $statusColor = $statusColors[$word] 
          break
        }
      }
    }
    else 
    {
      if ($statusType = 'Numeric') 
      {
        #Check the status value against the threshhold and if less than then if less than by more than half return red else return orange, if greater than then return green
        $num = [regex]::Match($statusText, '(\d+[.]\d+)|(\d+)')
        #ensure the value is a number
        try
        {
          $y = 0.00
          $x = 0.00
          if (!([string]::IsNullOrEmpty($num.Value))) 
          {
            if (!([float]::TryParse($num.Value, [ref]$y))) {
              $y = 1 #prevent div by zero
            }
          }
          if ($statusThresholdValue -ne '0') 
          {
            if (!([float]::TryParse($statusThresholdValue, [ref]$x))) {
              $x = 1
            }

            if ($y -le $x) 
            {
              $statusColor = $statcolOrange 
            }
            else 
            {
              $statusColor = $statcolGreen 
            }
          }
        }
        catch { $errList += (Get-ErrorObject) }
      }
    }
  }
  catch { $errList += (Get-ErrorObject) }
  $returnColor = New-Object -TypeName PSObject -Property @{
    statColor = [string]$statusColor
    statIcon  = $indicatorIconSet[[string]$statusColor]
  }
  if ($returnColor.Count -gt 1) { return $null } else { return $returnColor }
}
function script:IsFeatureSupported
{
  #Get PowerShell version currently in use and return capability to execute requested functionality - production code should cater for plan B in the case of a false result
  param
  (
    [string]
    [Parameter(Mandatory = $true, HelpMessage = 'The name of the object class to be tested.')]
    $testClassName
  )
  $sVersionInfo = $PSVersionTable.PSVersion
  $sVersionInfo
}
function CreateSubReport
{
  param
  (
    [string]
    [Parameter(Mandatory = $true, HelpMessage = 'Subfolder in which to save sub report')]
    $repSubFolder,
    [string]
    [Parameter(Mandatory = $true, HelpMessage = 'Report Title - will be used for saving, title and heading')]
    $repTitle,
    [Parameter(Mandatory = $true, HelpMessage = 'Object containing report data')]
    $InputObject,
    [ref]$repLink = '<a href="{0}" target=_blank>NA</a>' -f $varDash  
  )
  $repObj = [object[]]$(($InputObject).PSObject.Properties | Where-Object { $_.Value -ne $null } | Where-Object {$_.Value -is [string]} | Select-Object -Property Name, Value)
  try
  {
    
    if (!($repSubFolder.EndsWith($backSlash))) 
    {
      $repSubFolder += $backSlash
    }
    $uid = New-Guid
    $uid = [string]$uid.Guid.Replace($varDash,'')  
    $repFolder = ('{0}{1}' -f $baseReportDir, $repSubFolder)
    if (!(Test-Path -Path $repFolder)) 
    {
      $null = New-Item -Path $repFolder -ItemType Directory -Force
    }
    $repSaveName = ('{0}{1}{2}{3}.html' -f $baseReportDir, $repSubFolder, $repTitle, $uid)
  
    New-HTML -TitleText $repTitle -Online:$true -FilePath $repSaveName -HtmlData {
      New-HTMLSection -HeaderBackGroundColor Snow -Content {
        New-HTMLPanel -BackgroundColor Snow -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Detail Report for {0}' -f $repTitle) -FontSize 18 -Color Snow -Alignment center -FontWeight bold
          }
          New-HTMLTable -ArrayOfObjects $repObj -HideFooter -PagingOptions @(50, 100, 150, 200) -InvokeHTMLTags
        } #New Panel  
      } #New-HTMLContent   
    }  
  }
  catch 
  {
    $errList += (Get-ErrorObject)
  }
  $repLink.Value = '<a href="{0}" target=_blank>Details</a>' -f $repSaveName    
}
function Convert-MemoryUnits
{
  param
  (
    [switch]
    $UseDynamicUnit = $true,
    [float]
    [Parameter(Mandatory = $true, HelpMessage = 'Value to convert')]
    $ValueToConvert
  )

  $varUnitGB = 'GB'
  $tmpConvert = ([math]::Round($ValueToConvert * 1KB / 1GB, 2))
  Return ([string]$tmpConvert + $varUnitGB)
}
Function Get-HostUptime 
{
  param ([Parameter(Mandatory = $true, HelpMessage = 'Hostname')][string]$ComputerName)
  $Uptime = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName
  $LastBootUpTime = $Uptime.ConvertToDateTime($Uptime.LastBootUpTime)
  $Time = (Get-Date) - $LastBootUpTime
  Return '{0:00} Days, {1:00} Hours, {2:00} Minutes, {3:00} Seconds' -f $Time.Days, $Time.Hours, $Time.Minutes, $Time.Seconds
}

function Script:Cut-Path 
{
  param
  (
    [String]
    [Parameter(Mandatory)]
    $inputString
  )
    
  $backSlash = '\'
  $start = $inputString.LastIndexOf($backSlash)
  $strr = $inputString.SubString(0,$start)
  $start = $strr.LastIndexOf($backSlash)
  $s = $inputString.SubString($start)
  return $s
}
#endregion Functions

$tmr = [Diagnostics.Stopwatch]::StartNew()

#region Get Processes
Write-Progress -Activity $MainProgressMsgText -CurrentOperation 'Getting list of running processes...' -PercentComplete ($percs[(Get-CurrentLineNumber)])
$sysProcesses = [object[]]$(Get-WmiObject -Class Win32_PerfFormattedData_PerfProc_Process  -ComputerName $computer -Namespace $namespace | Select-Object -Property * -ExcludeProperty __CLASS, __DERIVATION, __DYNASTY, __GENUS, __NAMESPACE, __PATH, __PROPERTY_COUNT, __RELPATH, __SERVER, __SUPERCLASS, Scope, Path, Options, ClassPath, Properties, SystemProperties, Qualifiers, Site, Container | Sort-Object -Property Name)
$repProcesses = New-Object -TypeName System.Collections.Generic.List[System.Object]
ForEach ($p in $sysProcesses) 
{
  #CreateSubReport -repSubFolder 'procDetails' -repTitle ('{0}' -f $p.Name) -inputObject $p -repLink ([ref]$repLink)   
  $repProcesses += [object[]]$($p | Select-Object -Property IDProcess, Name, HandleCount, IODataOperationsPersec, @{
      n = 'ParentProcess'
      e = { (Get-ParentProcess -childID $p.CreatingProcessID) }
    }, @{
      n = 'ElapsedTime (mins)'
      e = {
        ([math]::Round($p.ElapsedTime / 60, 0))
      }
    }, @{
      n = 'WorkingSet'
      e = {
        $ws = $p.WorkingSet
        $mv = ''
        (Convert-MemoryUnits -ValueToConvert $ws)
      }
  })
} 

$dataCollectionTimes += (Get-SectionDurationObject -tmrObject $tmr -secCount $repProcesses.Count -secName 'Running process details')
$tmr.Restart()
#endregion

#region Services data
$detailServices = Get-Service | Select-Object -Property *
$flaggedServices = $detailServices | Select-Object -Property DisplayName, Name, Status, StartType | Get-ServiceBadState
$runningServices = $detailServices | Get-ServiceByStatus -serviceFilter 'Running'
$stoppedServices = $detailServices | Get-ServiceByStatus -serviceFilter 'Stopped'
$disabledServices = $detailServices | Get-ServiceByStatus -filterField 'StartType' -serviceFilter 'Disabled'

$dataCollectionTimes += (Get-SectionDurationObject -tmrObject $tmr -secCount $detailServices.Count -secName 'Services')
$tmr.Restart()

#endregion

#region Get installed applications
Write-Progress -Activity $MainProgressMsgText -CurrentOperation 'Getting list of installed programs...' -PercentComplete ($percs[(Get-CurrentLineNumber)])
$installedApps = [object[]]$(Get-ItemProperty -Path $RegKey)
$repUpdates = New-Object -TypeName System.Collections.Generic.List[System.Object]
$repDOTNET = New-Object -TypeName System.Collections.Generic.List[System.Object]
$repSQLApps = New-Object -TypeName System.Collections.Generic.List[System.Object]

$repSQLApps = Get-InstalledApps -allAppsObject $installedApps -filterValue 'SQL'
$repDOTNET = (Get-DotNetVersion -LocalHost -NoSummary -ContinueOnPingFail)
$repUpdates = Get-InstalledApps -allAppsObject $installedApps -filterValue 'Update*Microsoft'
$repHotfixes = [object[]]$(Get-HotFix) | Select-Object -Property HotFixId, Description, FixComments, InstallDate, InstalledBy, @{
  n = 'About'
  e = {
    if (!([string]::IsNullOrEmpty($_.Caption))) {
      (Make-ItALink -linkURL $_.Caption -linkText 'About')     
    }
  }
}

$dataCollectionTimes += (Get-SectionDurationObject -tmrObject $tmr -secCount $installedApps.Count -secName 'Installed software details')
$tmr.Restart()
#endregion Installed applications

Write-Progress -Activity $MainProgressMsgText -CurrentOperation 'Getting OS information...' -PercentComplete ($percs[(Get-CurrentLineNumber)])

#region OS Information
$osInfo = [object[]]$(Get-WmiObject -Class Win32_OperatingSystem)
$osReportFields = $osInfo | Select-Object -Property Caption, Version, OSArchitecture, Primary, Status, NumberOfProcesses, NumberOfUsers
$statOS = Get-SectionStatus -statusText $osReportFields.Status -statusThresholdValue 0 -statusType 'Alpha'
$hostUptime = Get-HostUptime -ComputerName $LocalHostText
$compSystem = [object[]]$(Get-WmiObject -Class  Win32_ComputerSystem)

$dataCollectionTimes += (Get-SectionDurationObject -tmrObject $tmr -secCount $osInfo.Count -secName 'OS details')
$tmr.Restart()
#endregion OS Information

#region BIOS Information
Write-Progress -Activity $MainProgressMsgText -CurrentOperation 'Getting BIOS information...' -PercentComplete ($percs[(Get-CurrentLineNumber)])
$sysBIOS = [object[]]$(Get-WmiObject -Class Win32_BIOS | Select-Object -Property * -ExcludeProperty __CLASS, __DERIVATION, __DYNASTY, __GENUS, __NAMESPACE, __PATH, __PROPERTY_COUNT, __RELPATH, __SERVER, __SUPERCLASS, Scope, Path, Options, ClassPath, Properties, SystemProperties, Qualifiers, Site, Container)
$biosStat = Get-SectionStatus -statusText $sysBIOS.Status -statusType 'Alpha'  
$null = $repBIOS.Clear
foreach ($bios in $sysBIOS)
{
  CreateSubReport -repSubFolder 'biosDetails' -repTitle ('BIOS_Details_{0}' -f $bios.SerialNumber) -InputObject $bios -repLink ([ref]$repLink)
  $repBIOS += [object[]]$($bios | Select-Object -Property Manufacturer, Version, SerialNumber, Status, @{
      n = $detailLinkText
      e = {
        $repLink
      }
  })
}

$dataCollectionTimes += (Get-SectionDurationObject -tmrObject $tmr -secCount $sysBIOS.Count -secName 'BIOS details')
$tmr.Restart()
#endregion BIOS Information

#region CPU Information
Write-Progress -Activity $MainProgressMsgText -CurrentOperation 'Getting CPU information...' -PercentComplete ($percs[(Get-CurrentLineNumber)])
$sysCPU = [object[]]$(Get-WmiObject -Class Win32_Processor | Select-Object -Property * -ExcludeProperty __CLASS, __DERIVATION, __DYNASTY, __GENUS, __NAMESPACE, __PATH, __PROPERTY_COUNT, __RELPATH, __SERVER, __SUPERCLASS, Scope, Path, Options, ClassPath, Properties, SystemProperties, Qualifiers, Site, Container)
if ($sysCPU.NumberOfLogicalProcessors -gt $sysCPU.NumberOfCores) 
{
  $sysHyperThreaded = $true
}
else 
{
  $sysHyperThreaded = $false
}
$null = $repCPU.Clear
foreach ($cpu in $sysCPU) 
{ 
  CreateSubReport -repSubFolder 'cpuDetails' -repTitle ('CPU_Details_{0}' -f $cpu.DeviceID) -InputObject $cpu -repLink ([ref]$repLink)
  $cpuStat = Get-SectionStatus -statusText 80 -statusThresholdValue $cpu.LoadPercentage -statusType 'Numeric'  #switch actual and threshhold because high is bad and low is good unlike most other checks
  $repCPU += [object[]]$($cpu | Select-Object -Property Name, @{
      n = 'Load'
      e = {
        ('{0}' -f $cpu.LoadPercentage)
      }
    }, @{
      n = 'Cores'
      e = {
        ('{0}' -f $cpu.NumberOfCores)
      }
    }, @{
      n = 'Logical_Processors'
      e = {
        ('{0}' -f $cpu.NumberOfLogicalProcessors)
      }
    }, @{
      n = 'Status'
      e = {
        ('{0} - {1}' -f $procAvailability.Item([int]$sysCPU.Availability), $cpu.Status)
      }
    }, @{
      n = $detailLinkText
      e = {
        $repLink
      }
  }) 
}

$dataCollectionTimes += (Get-SectionDurationObject -tmrObject $tmr -secCount $sysCPU.Count -secName 'CPU details')
$tmr.Restart()
#endregion CPU Information

#region Memory (RAM) Information
Write-Progress -Activity $MainProgressMsgText -CurrentOperation 'Getting Memory information...' -PercentComplete ($percs[(Get-CurrentLineNumber)])

$osInfoForMem =  Get-WmiObject -Class WIN32_OperatingSystem
$sysMem = [object[]]$(Get-WmiObject -Class Win32_PhysicalMemory | Select-Object -Property * -ExcludeProperty __CLASS, __DERIVATION, __DYNASTY, __GENUS, __NAMESPACE, __PATH, __PROPERTY_COUNT, __RELPATH, __SERVER, __SUPERCLASS, Scope, Path, Options, ClassPath, Properties, SystemProperties, Qualifiers, Site, Container)
$totMem = (Convert-MemoryUnits -UseDynamicUnit -ValueToConvert $osInfoForMem.TotalVisibleMemorySize)
$freeMem = (Convert-MemoryUnits -UseDynamicUnit -ValueToConvert $osInfoForMem.FreePhysicalMemory)

if (([string]::IsNullOrEmpty($freeMem))) {
  $freeMem = '0'
}
$memStat = Get-SectionStatus -statusText $freeMem -statusThresholdValue ($totMem / 3.00) -statusType 'Numeric'

$null = $repMEM.Clear
foreach ($mem in $sysMem)
{
  CreateSubReport -repSubFolder 'memDetails' -repTitle ('Memory_Details_{0}' -f $mem.BankLabel) -InputObject $mem -repLink ([ref]$repLink)
  $repMEM += [object[]]$($mem | Select-Object -Property Manufacturer, MemoryType, SerialNumber, Speed, Tag, @{
      n = 'FreeMemory'
      e = {
        ('{0}' -f $freeMem)
      }
    }, @{
      n = $detailLinkText
      e = {
        $repLink
      }
  })
}

$dataCollectionTimes += (Get-SectionDurationObject -tmrObject $tmr -secCount $sysMem.Count -secName 'Memory details')
$tmr.Restart()
#endregion Memory (RAM) Information

#region Disk information
Write-Progress -Activity $MainProgressMsgText -CurrentOperation 'Getting Disk/s information...' -PercentComplete ($percs[(Get-CurrentLineNumber)])
$sysDiskInfo = [object[]]$(Get-WmiObject -Class Win32_LogicalDisk | Select-Object -Property * -ExcludeProperty __CLASS, __DERIVATION, __DYNASTY, __GENUS, __NAMESPACE, __PATH, __PROPERTY_COUNT, __RELPATH, __SERVER, __SUPERCLASS, Scope, Path, Options, ClassPath, Properties, SystemProperties, Qualifiers, Site, Container)

$discStat = (Get-SectionStatus -statusText @repDisk)

$diskinfo = (Get-CimInstance -Class CIM_LogicalDisk | Select-Object -Property DeviceID, DriveType, VolumeName, VolumeSerialNumber, FileSystem, Compressed, Size, Freespace,
  @{
    n = 'Size(GB)'
    e = {
                 if (($_.freespace -ne 0) -and ($_.size -ne 0)) {
                   '{0}' -f ($_.size/1gb)
                 } else {
                   'Err'
                 } 
        }
  },
  @{
    n = 'Free Space(GB)'
    e = {
                 if (($_.freespace -ne 0) -and ($_.size -ne 0)) {
                   '{0}' -f ($_.freespace/1gb)
                 } else {
                   'Err'
                 }
        }                     
  },
  @{
    n = 'Percent Free'
    e = {
                 if (($_.freespace -ne 0) -and ($_.size -ne 0)) {
                   '{0}' -f ((($_.freespace/1gb) / ($_.size/1gb)) * 100)
                 } else {
                   'Err'
                 }
        }
               
  } | Where-Object DriveType -eq '3')
                

$null = $repDisk.Clear
foreach ($disk in $diskinfo) 
{
  CreateSubReport -repSubFolder 'diskDetails' -repTitle ('Disk_Details_{0}' -f $disk.VolumeName) -InputObject $disk -repLink ([ref]$repLink)
  $repDisk += [object[]]$($disk | Select-Object -Property VolumeName, DeviceID, VolumeSerialNumber, FileSystem, Compressed, @{  
      n = 'Size (GB)'
      e = {
            ('{0}' -f [math]::Round($disk.'Size(GB)',2))
          }
    }, @{
      n = 'Free Space (GB)'
      e = {
            ('{0}' -f [math]::Round($disk.'Free Space(GB)',2))
          }
    }, @{
      n = 'Percent Free'
      e = {
            ('{0}' -f [math]::Round($disk.'Percent Free',2))
          }
    }, @{
      n = $detailLinkText
      e = {
        $repLink
      }
  })
}
$dataCollectionTimes += (Get-SectionDurationObject -tmrObject $tmr -secCount $sysDiskInfo.Count -secName 'Disk details')
$tmr.Restart()
#endregion Disk information

#region Port information
Write-Progress -Activity $MainProgressMsgText -CurrentOperation 'Getting Port information...' -PercentComplete ($percs[(Get-CurrentLineNumber)])
$portList = Select-PortData 
$estPorts = $portList | Select-PortsByState -portFilter 'Established' | Select-Object -Property *
$listeningPorts = $portList | Select-PortsByState -portFilter 'Listen' | Select-Object -Property *
$boundPorts = $portList | Select-PortsByState -portFilter 'Bound' | Select-Object -Property *

$dataCollectionTimes += (Get-SectionDurationObject -tmrObject $tmr -secCount $portList.Count -secName 'Port details')
$tmr.Restart()
#endregion Port information

#region Get event logs
Write-Progress -Activity $MainProgressMsgText -CurrentOperation 'Getting Event Logs...' -PercentComplete ($percs[(Get-CurrentLineNumber)])
$eventsFrom = (Get-Date) - (New-TimeSpan -Hours 1)
$eventLogs = Select-EventLogList
$getAppLog = $eventLogs | Select-EventLogIsApplication
if ($getAppLog) {
   $ApplicationEvents = (Get-EventLogCustom -logName 'Application')
}

$dataCollectionTimes += (Get-SectionDurationObject -tmrObject $tmr -secCount $eventLogs.Count -secName 'Event Logs')
$tmr.Restart()
#endregion Get event logs

#region Performance Counters
Write-Progress -Activity $MainProgressMsgText -CurrentOperation 'Getting Performance Counters...' -PercentComplete ($percs[(Get-CurrentLineNumber)])

$memCounters = (Get-CounterByName -counterName 'Memory')
$procCounters = (Get-CounterByName -counterName 'Processor')
$sharesCounters = (Get-CounterByName -counterName 'SMB Server Shares')
$totalCounters = ($memCounters.Count + $procCounters.Count + $sharesCounters.Count)

$dataCollectionTimes += (Get-SectionDurationObject -tmrObject $tmr -secCount $totalCounters -secName 'Performance Counters')
$tmr.Restart()
#endregion Performance Counters

#region Network Adaptor information
Write-Progress -Activity $MainProgressMsgText -CurrentOperation 'Getting Network Adaptor Details...' -PercentComplete ($percs[(Get-CurrentLineNumber)])
$netInfo = [object[]]$(Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object -Property IPEnabled | Select-Object -Property * -ExcludeProperty __CLASS, __DERIVATION, __DYNASTY, __GENUS, __NAMESPACE, __PATH, __PROPERTY_COUNT, __RELPATH, __SERVER, __SUPERCLASS, Scope, Path, Options, ClassPath, Properties, SystemProperties, Qualifiers, Site, Container)
$repNet = New-Object -TypeName System.Collections.Generic.List[System.Object]
foreach ($net in $netInfo) 
{
  CreateSubReport -repSubFolder 'netDetails' -repTitle ('Net_Details_{0}' -f $net.Description) -InputObject $net -repLink ([ref]$repLink)
  $repNet += [object[]]$($net | Select-Object -Property Description, DHCPEnabled, DHCPServer, @{
      n = 'IPAddress/es'
      e = {
        Get-FieldValuesAsHTMLList -inputObject ($net | Select-Object -ExpandProperty IPAddress) 
      }
    }, @{
      n = 'IPSubNet'
      e = {
        Get-FieldValuesAsHTMLList -inputObject ($net | Select-Object -ExpandProperty IPSubNet) 
      }
    }, MACAddress, @{
      n = 'DefaultGateWay'
      e = {
        Get-FieldValuesAsHTMLList -inputObject ($net | Select-Object -ExpandProperty DefaultIPGateway) 
      }
    }, @{
      n = $detailLinkText
      e = {
        $repLink
      }    
  }) 
}
$dataCollectionTimes += (Get-SectionDurationObject -tmrObject $tmr -secCount $netInfo.Count -secName 'Network Adaptors')
$tmr.Restart()
#endregion Network Adaptor information

#region General Information
$timezone = [object[]]$(Get-WmiObject -Class Win32_TimeZone -ComputerName $computer -Namespace $namespace)
$bootinfo = [object[]]$(Get-WmiObject -Class Win32_BootConfiguration -ComputerName $computer -Namespace $namespace)
$dispInfo = [object[]]$(Get-WmiObject -Class Win32_DisplayConfiguration -ComputerName $computer -Namespace $namespace)
$enviInfo = [object[]]$(Get-WmiObject -Class Win32_Environment | Select-Object -Property Name, VariableValue | Where-Object -FilterScript { $_.VariableValue -ne '' } | Sort-Object -Unique -Property Name)
$sysLocale = [object[]]$(Get-WinSystemLocale | Select-Object -Property DisplayName, DateTimeFormat, NumberFormat)
$localeDT = [object[]]$(($sysLocale | Select-Object -ExpandProperty DateTimeFormat).PSObject.Properties | Where-Object {$_.Value -ne $null}) | Where-Object {$_.Value -is [string]} | Select-Object -Property Name, Value
$localeNum = [object[]]$(($sysLocale | Select-Object -ExpandProperty NumberFormat).PSObject.Properties | Where-Object {$_.Value -ne $null}) | Where-Object {$_.Value -is [string]} | Select-Object -Property Name, Value
#endregion General Information
#endregion Collection of data

#if ($outputHTML) {

  #region Build and display report
  Write-Progress -Activity $MainProgressMsgText -CurrentOperation 'Generating report HTML...' -PercentComplete ($percs[(Get-CurrentLineNumber)])
  
  New-HTML -TitleText 'System Report' -Online:$true -FilePath $reportSaveName -ShowHTML -HtmlData {
   
    New-HTMLTabStyle -SlimTabs -SelectorColor DarkSlateGrey -SelectorColorTarget LightGrey -LinearGradient -Direction row -Align center -AlignContent center -AlignItems center
    New-HTMLTableStyle -TextAlign left -Type Row
    New-HTMLTableStyle -TextAlign left -BorderLeftWidthSize 0 -Type Header
   
    New-HTMLTab -Name 'System Overview' -HtmlData {
      New-HTMLSection -HeaderBackGroundColor Snow -Invisible -Content {
        New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
          New-HTMLText -Text ('Report date: {0} - User: {1} - Execution Policy: {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),($env:UserName),(Get-ExecutionPolicy)) -FontSize 18 -Color LightCyan -Alignment center -FontWeight bold 
        }
      }    
      New-HTMLSection -HeaderBackGroundColor Snow -Content {
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('System Status - {0} ' -f $compSystem.Name) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }  
          New-HTMLToast -IconSolid info-circle -IconColor Red -BarColorLeft Red -TextHeader 'Important Information' -Text 'This report is best viewed in Chrome. Please allow blocked content if prompted. Some features may be hidden or disabled by browser settings.'
          New-HTMLToast -IconSolid brain -IconColor $cpuStat.statColor -BarColorLeft $cpuStat.statColor -TextHeader 'CPU' -Text ('{0} (Cores: {1} - Logical Processors: {2} - Hyperthreading: {3} - Load: {4})' -f $repCPU.Name, $repCPU.Cores, $repCPU.Logical_Processors, $sysHyperThreaded, $repCPU.Load)             
          New-HTMLToast -IconSolid memory -IconColor $memStat.statColor -TextHeader 'Memory' -BarColorLeft $memStat.statColor -Text ('Visible: {0} - Available: {1}' -f ($totMem), ($freeMem)) 
          New-HTMLToast -IconSolid desktop -IconColor $statOS.statColor -TextHeader 'OS' -BarColorLeft $statOS.statColor -Text ('{0} - Version: {1} - Status: {2}' -f $osReportFields.Caption, $osReportFields.Version, $osReportFields.Status)
          New-HTMLToast -IconSolid atom -IconColor $biosStat.statColor -TextHeader 'BIOS' -BarColorLeft $biosStat.statColor -Text ('{0} - Serial Number: {1} - Status: {2}' -f [string]$repBIOS.Version, $repBIOS.SerialNumber, $repBIOS.Status)
          #New-HTMLToast -IconSolid compact-disc -IconColor
          New-HTMLSection -HeaderBackGroundColor Snow -Content {
            New-HTMLPanel -BackgroundColor LightGrey -Content {
              New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
                New-HTMLText -Text 'System summary' -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
              }
              New-HTMLList -Type Unordered -Alignment left -BackGroundColor Snow -Color DarkSlateGrey -FontSize 14 -FontWeight bold -ListItems {
                New-HTMLListItem -Text ('Make: {0}' -f $compSystem.Manufacturer)
                New-HTMLListItem -Text ('Model: {0}' -f $compSystem.Model)
                New-HTMLListItem -Text ('Uptime: {0}' -f $hostUptime) 
                New-HTMLListItem -Text ('Boot State: {0}' -f $compSystem.BootupState)               
                New-HTMLListItem -Text ('Built using PowerShell v{0}, {1}' -f $PSVersionTable.PSEdition, $PSVersionTable.PSVersion, $PSVersionTable.BuildVersion)        
                New-HTMLListItem -Text ('Time zone: {0} - {1}' -f $timezone.Description, $timezone.StandardName)
                New-HTMLListItem -Text ('Boot Directory: {0}' -f $bootinfo.Description)
                New-HTMLListItem -Text ('Display ({0}): Res: {1} X {2}' -f $dispInfo.Description, $dispInfo.PelsWidth, $dispInfo.PelsHeight)
              }
              New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
                New-HTMLText -Text 'Report information by section' -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
              }
              New-HTMLList -Type Unordered -BackGroundColor LightGrey -Color DarkSlateGrey -FontSize 14 -FontWeight bold -ListItems {
                foreach ($thing in $dataCollectionTimes) 
                {
                  New-HTMLListItem -Text ('{0} {1} loaded in {2}' -f $thing.Count, $thing.Section, $thing.Duration) 
                }
              }  
              if ($errList.Count -gt 0) {
                New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
                  New-HTMLText -Text ('Report Error Log ({0})' -f $errList.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
                }
                New-HTMLTable -ArrayOfObjects $errList -HideFooter -InvokeHTMLTags -DisablePaging -DisableSearch -Buttons copyHtml5                      
              } else {
                New-HTMLPanel -BackgroundColor Green -Content {
                  New-HTMLText -Text 'Report Error Log (0)' -FontSize 18 -BackGroundColor Snow -Alignment center -FontWeight bold 
                }              
              }
            }
            New-HTMLPanel -BackgroundColor LightGrey -Content {
              New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
                New-HTMLText -Text 'System locale' -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
              }
              New-HTMLPanel -BackgroundColor SlateGrey -Content {
                New-HTMLText -Text 'Date Time' -FontSize 14 -Color Snow -Alignment center -FontWeight bold 
              }            
              New-HTMLTable -ArrayOfObjects $localeDT -HideFooter -InvokeHTMLTags -DisablePaging -DisableSearch -Buttons copyHtml5
              New-HTMLPanel -BackgroundColor SlateGrey -Content {
                New-HTMLText -Text 'Numeric' -FontSize 14 -Color Snow -Alignment center -FontWeight bold 
              }              
              New-HTMLTable -ArrayOfObjects $localeNum -HideFooter -InvokeHTMLTags -DisablePaging -DisableSearch -Buttons copyHtml5
            }
          }
        }   
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Memory (Free: {0})' -f $freeMem) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $repMEM -HideFooter -InvokeHTMLTags -DisablePaging -DisableSearch -Buttons copyHtml5 -HTML {
            New-TableCondition -Name 'FreeMemory' -ComparisonType string -Operator notlike -Value 'foobar' -BackgroundColor $memStat.statColor -Color White
          }
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('CPU ({0})' -f $repCPU.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $repCPU -HideFooter -InvokeHTMLTags -DisablePaging -DisableSearch -Buttons copyHtml5 -HTML {
            New-TableCondition -Name 'Load' -ComparisonType number -Operator gt -Value 80 -BackgroundColor Crimson -Color Snow
            New-TableCondition -Name 'Status' -ComparisonType string -Operator notlike -Value 'foobar' -BackgroundColor $cpuStat.statColor -Color Snow
          }   
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Disks ({0})' -f $repDisk.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $repDisk -HideFooter -InvokeHTMLTags -DisablePaging -DisableSearch -Buttons copyHtml5 -HTML {
            New-TableCondition -Name 'Free Space (GB)' -ComparisonType number -Operator lt -Value 30.00 -BackgroundColor Crimson -Color White
            New-TableCondition -Name 'Free Space (GB)' -ComparisonType number -Operator gt -Value 30.00 -BackgroundColor ForestGreen -Color White
          }             
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text 'BIOS' -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -DataTable $repBIOS -HideFooter -InvokeHTMLTags -DisablePaging -DisableSearch -Buttons copyHtml5 -HTML { 
            New-TableCondition -Name 'Status' -ComparisonType string -Operator notlike -Value 'foobar' -BackgroundColor $biosStat.statColor -Color Snow 
          }     
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Network Adaptors ({0})' -f $repNet.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $repNet -HideFooter -InvokeHTMLTags -DisablePaging -DisableSearch -Buttons copyHtml5          
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Environment Variables ({0})' -f $enviInfo.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLList -Type Unordered -BackGroundColor LightGrey -Color DarkSlateGrey -FontSize 14 -FontWeight bold -ListItems {
            foreach ($en in $enviInfo) {
              New-HTMLListItem -Text ('{0}: {1}' -f $en.Name, $en.VariableValue)
            }
          }        
        } #New Panel        
      }#New-HTMLSection
    }
    New-HTMLTab -Name 'Perf Counters' -HtmlData {
      New-HTMLSection -HeaderBackGroundColor Snow -Invisible -Content {
        New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
          New-HTMLText -Text ('Report date: {0} - User: {1} - Execution Policy: {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),($env:UserName),(Get-ExecutionPolicy)) -FontSize 18 -Color LightCyan -Alignment center -FontWeight bold 
        }
      }     
      New-HTMLSection -HeaderBackGroundColor Snow -Content {
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Memory Counters ({0})' -f $memCounters.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $memCounters -InvokeHTMLTags -DefaultSortColumn 'Name' -HideFooter -PagingOptions @(50, 100, 150, 200)
        } #New Panel 
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Processor Counters ({0})' -f $procCounters.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $procCounters -HideFooter -InvokeHTMLTags -PagingOptions @(50, 100, 150, 200)
        } #New Panel  
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('SMB Server Shares Counters ({0})' -f $sharesCounters.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $sharesCounters -HideFooter -InvokeHTMLTags -PagingOptions @(50, 100, 150, 200)
        } #New Panel  
      } #New-HTMLContent   
    }  
    New-HTMLTab -Name 'Event Logs' -HtmlData {
      New-HTMLSection -HeaderBackGroundColor Snow -Invisible -Content {
        New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
          New-HTMLText -Text ('Report date: {0} - User: {1} - Execution Policy: {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),($env:UserName),(Get-ExecutionPolicy)) -FontSize 18 -Color LightCyan -Alignment center -FontWeight bold 
        }
      }     
      New-HTMLSection -HeaderBackGroundColor Snow -Content {
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Available event logs ({0})' -f $eventLogs.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          if ([string]::IsNullOrEmpty($getAppLog)) 
          {
            New-HTMLPanel -BackgroundColor Crimson -Content {
              New-HTMLText -Text 'Application Event Log Failed to Load!' -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
            }
          }
          New-HTMLTable -ArrayOfObjects $eventLogs -InvokeHTMLTags -DefaultSortColumn 'Name' -HideFooter -PagingOptions @(50, 100, 150, 200)
        } #New Panel 
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Application Event Log Latest {0} ({1})' -f $eventsFrom, $ApplicationEvents.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $ApplicationEvents -HideFooter -InvokeHTMLTags -PagingOptions @(50, 100, 150, 200)
        } #New Panel  
      } #New-HTMLContent  
    }  
    New-HTMLTab -Name 'Services & Processes' -HtmlData {
      New-HTMLSection -HeaderBackGroundColor Snow -Invisible -Content {
        New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
          New-HTMLText -Text ('Report date: {0} - User: {1} - Execution Policy: {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),($env:UserName),(Get-ExecutionPolicy)) -FontSize 18 -Color LightCyan -Alignment center -FontWeight bold 
        }
      }     
      New-HTMLSection -HeaderBackGroundColor Snow -Content {
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor Crimson -Content {
            New-HTMLText -Text ('Flagged Services ({0})' -f $flaggedServices.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold
            New-HTMLText -Text 'The following services are flagged because they are in a Stopped state but have a start up type of Automatic' -FontSize 13 -Color Snow -Alignment center
          }
          New-HTMLTable -ArrayOfObjects $flaggedServices -InvokeHTMLTags -DefaultSortColumn 'StartTime' -HideFooter -PagingOptions @(50, 100, 150, 200)
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Running Services ({0})' -f $runningServices.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $runningServices -HideFooter -InvokeHTMLTags -PagingOptions @(50, 100, 150, 200)         
        } #New Panel 
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Running processes ({0})' -f $repProcesses.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $repProcesses -InvokeHTMLTags -DefaultSortColumn 'StartTime' -HideFooter -PagingOptions @(50, 100, 150, 200)
        } #New Panel        
      } #New-HTMLContent   
      New-HTMLSection -HeaderBackGroundColor Snow -Content {
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Stopped Services ({0})' -f $stoppedServices.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $stoppedServices -HideFooter -InvokeHTMLTags -PagingOptions @(50, 100, 150, 200)
        } #New Panel 
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Disabled Services ({0})' -f $disabledServices.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $disabledServices -HideFooter -InvokeHTMLTags -PagingOptions @(50, 100, 150, 200)
        } #New Panel 
      } #New-HTMLContent       
    } #New-HTMLTab
    New-HTMLTab -Name 'Ports' -AnchorName 'Ports' -HtmlData {
      New-HTMLSection -HeaderBackGroundColor Snow -Invisible -Content {
        New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
          New-HTMLText -Text ('Report date: {0} - User: {1} - Execution Policy: {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),($env:UserName),(Get-ExecutionPolicy)) -FontSize 18 -Color LightCyan -Alignment center -FontWeight bold 
        }
      }     
      New-HTMLSection -HeaderBackGroundColor Snow -Content {
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Established Ports ({0})' -f $estPorts.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $estPorts -InvokeHTMLTags -HideFooter -PagingOptions @(50, 100, 150, 200) 
        } #New Panel  
      }
      New-HTMLSection -HeaderBackGroundColor Snow -Content {    
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Listening Ports ({0})' -f $listeningPorts.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $listeningPorts -InvokeHTMLTags -HideFooter -PagingOptions @(50, 100, 150, 200)
        } #New Panel        
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Bound Ports ({0})' -f $boundPorts.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $boundPorts -InvokeHTMLTags -HideFooter -PagingOptions @(50, 100, 150, 200)
        } #New Panel    
      } #New-HTMLContent   
    }    
    New-HTMLTab -Name 'Software' -HtmlData {
      New-HTMLSection -HeaderBackGroundColor Snow -Invisible -Content {
        New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
          New-HTMLText -Text ('Report date: {0} - User: {1} - Execution Policy: {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),($env:UserName),(Get-ExecutionPolicy)) -FontSize 18 -Color LightCyan -Alignment center -FontWeight bold 
        }
      }     
      New-HTMLSection -HeaderBackGroundColor Snow -Content {
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Installed .NET Components') -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $repDOTNET -HideFooter -InvokeHTMLTags -PagingOptions @(50, 100, 150, 200)  
        } #New Panel  
      } #New-HTMLContent   
      New-HTMLSection -HeaderBackGroundColor Snow -Content {
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Installed SQL Components ({0})' -f $repSQLApps.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $repSQLApps -HideFooter -InvokeHTMLTags -PagingOptions @(50, 100, 150, 200)
        } #New Panel  
      } #New-HTMLContent      
      New-HTMLSection -HeaderBackGroundColor Snow -Content {
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Installed Microsoft Updates ({0})' -f $repUpdates.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $repUpdates -HideFooter -InvokeHTMLTags -PagingOptions @(50, 100, 150, 200)
        } #New Panel  
        New-HTMLPanel -BackgroundColor LightGrey -Content {
          New-HTMLPanel -BackgroundColor DarkSlateGrey -Content {
            New-HTMLText -Text ('Installed Hot Fixes ({0})' -f $repHotfixes.Count) -FontSize 18 -Color Snow -Alignment center -FontWeight bold 
          }
          New-HTMLTable -ArrayOfObjects $repHotfixes -HideFooter -InvokeHTMLTags -PagingOptions @(50, 100, 150, 200)
        } #New Panel  
      } #New-HTMLContent   
    } #New-HTMLTab    
  } #New-HTML
<#}
    else
    {
    #Output text file
    $textFile = New-Item $reportSaveName -ItemType file
    #$textFile.AppendText()
    }
#>Write-Progress -Activity $MainProgressMsgText -CurrentOperation 'Displaying report...' -PercentComplete ($percs[(Get-CurrentLineNumber)])
#endregion Build and display report
Write-Progress -Activity $MainProgressMsgText -CurrentOperation 'Done...' -PercentComplete 100 -Completed