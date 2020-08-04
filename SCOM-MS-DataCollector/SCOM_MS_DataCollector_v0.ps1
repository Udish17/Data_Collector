###################################################################################################################
######### This script will collect SCOM infrastrucutre details for Support Professional troubleshooting  ##########
#########                            Author: Udishman Mudiar (Udish)                                     ##########
#########                               Version 1.0                                                      ##########
###################################################################################################################

Write-Host "Script started.." -ForegroundColor Green
$sw = [Diagnostics.Stopwatch]::StartNew()
Start-Sleep 2

$date=Get-Date -Format "ddMMyyyy-HHmmss"

Function Write-Log($loglevel, $message){

    "$date `t $LogLevel `t $message" | Out-File C:\Temp\SCOMLogs\SCOMLog_$($Date).txt -Append

}

Function Get-LogPath(){
    
    Try{
        #Checking if the SCOM Logs folder exists.
        $logpath=Get-Item -Path C:\Temp\SCOMLogs -ErrorAction SilentlyContinue

        #Make sure no content is present in the SCOMLogs folder
        If($logpath -ne $null)
         {
           Write-Log "Info" "SCOM Log Path C:\Temp\SCOMLogs exist"
           #Get all items already present in the SCOMLogs folder
           $childfiles=Get-ChildItem -Path C:\Temp\SCOMLogs

           if($childfiles)
           {
                Write-Host "`nOld files found in C:\Temp\SCOMLogs. Cleaning up.." -ForegroundColor Cyan
                #Clear the old files from SCOMLogs folder
                $childfiles | Remove-Item -Recurse -Force
           }
         }
         Else
         {
            #Creating a new folder SCOMLogs as it is not present to store all logs.
            New-Item -Path C:\Temp -Name SCOMLogs -ItemType Directory | Out-Null        
            Write-Log "Info" "Create SCOM Log Path C:\Temp\SCOMLogs"
         
         }
      }
    Catch{
         $ErrorMessage = $_.Exception.Message
         Write-Host "`nUnable to create the logs folder" -ForegroundColor Red
         $ErrorMessage        
         Write-Log "Error" "Unable to create the logs folder"
         $ErrorMessage | Out-File C:\Temp\SCOMLogs\SCOMLog_$($Date).txt -Append
         Exit
    }
    
}

Function Check-IsAdministrator(){
    
    Write-Host "`nChecking if PowerShell is launched with Administrative Priviledge" -ForegroundColor Cyan
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $IsAdministrator=$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if($IsAdministrator -eq $false)
    {
        Write-Host "Exiting script..Launch the PowerShell session as administrator." -ForegroundColor Red
        Start-sleep 3
        Exit
    }
    else
    {
        Write-Host "Success: The PowerShell is launched with Administrative Priviledge" -ForegroundColor Green
        Write-Host "`nThe script will generate the required logs at C:\Temp\SCOMLogs" -ForegroundColor Cyan
    }
}

Function Install-Module(){
    Start-Sleep 2
    #Get the SCOM installation directory
    $InstallDir=(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup').InstallDirectory
    $OMPowerShellDir=$InstallDir.Replace('Server','PowerShell')

    If((Test-Path  $OMPowerShellDir) -eq "True")
    {
        $Modulepath=$OMPowerShellDir + "OperationsManager\OperationsManager.psd1"
    }
    Else
    {
        Write-Host "Operations Manager PowerShell path not found" -ForegroundColor Red
        Exit
    }

    #Importing SCOM module from Module Path
    Write-Host "`nImporting SCOM Module.." -ForegroundColor Cyan
    Try{
        #Importing SCOM Module here
        Import-Module $Modulepath        
        Write-Log "Info" "Operations Manager module imported"
    }
    Catch
    {
        $ErrorMessage = $_.Exception.Message
        Write-Host "`nUnable to import SCOM module" -ForegroundColor Red
        $ErrorMessage        
        Write-Log "Error" "Operations Manager module cannot be imported"
        $ErrorMessage | Out-File C:\Temp\SCOMLogs\SCOMLog_$($Date).txt -Append
        Exit
    }
}

Function Export-SystemData(){
    Start-Sleep 2
    Try{
        Write-Host "`nExporting system data.." -ForegroundColor Cyan
        #Getting the hostname of the MS
        hostname | Out-File C:\Temp\SCOMLogs\hostname.txt
        Write-Log "Info" "Exported hostname"
        #Getting the ip details of the MS
        ipconfig /all | Out-File C:\Temp\SCOMLogs\ipconfig.txt
        Write-Log "Info" "Exported ip details"
        #Getting the system information of the MS
        systeminfo | Out-File C:\Temp\SCOMLogs\systeminfo.txt
        Write-Log "Info" "Exported System Info"
    }
    Catch
    {
        $ErrorMessage = $_.Exception.Message
        Write-Host "`nUnable to export System Data" -ForegroundColor Red
        $ErrorMessage        
        Write-Log "Error" "Unable to export System Data"
        $ErrorMessage | Out-File C:\Temp\SCOMLogs\SCOMLog_$($Date).txt -Append
        Exit
    }
}

Function Export-SCOMInfraInfo(){

    Try
    {
        Start-Sleep 2
        Write-Host "`nExporting SCOM Infra details.." -ForegroundColor Cyan
        Write-Log "Info" "Connection to SCOM MS and collecting data.."
        #Connecting to SCOM MG
        New-SCOMManagementGroupConnection -ComputerName ([System.Net.Dns]::GetHostByName(($env:computerName)).hostname).string
        $SCOMMS=Get-SCOMManagementServer | where {$_.IsGateway -eq $False}
        $Gateway=Get-SCOMManagementServer | where {$_.IsGateway -eq $True}
        $Windowsagent=Get-SCOMAgent
        $SCXAgent=Get-SCXAgent
        $NetworkDevice= Get-SCOMClass -DisplayName "Node" | Get-SCOMClassInstance
        $agentlesscomputer=Get-SCOMGroup -DisplayName "Agentless Managed Computer Group" | Get-SCOMClassInstance
        $ManagementPacks=Get-SCOMManagementPack
        $SCOMGroup=Get-SCOMGroup
        $PendingAgent=Get-SCOMPendingManagement
        $URLMonitoring=get-scomclass -DisplayName "Web Application Perspective" | Get-SCOMClassInstance


        $SCOMFolder = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup").InstallDirectory
        $SCOMVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup").currentversion

        Write-Log "Info" "Exporting SCOM version and UR details.."
        If($SCOMversion -eq "7.2.11719.0")
        {
            $SCOMProductVersion = "SCOM 2016"
            $URVersion  = Get-ChildItem -Path $SCOMFolder | where {$_.Name -eq "Microsoft.EnterpriseManagement.DataAccessLayer.dll"} | FT @{Label="FileVersion";Expression={$_.Versioninfo.FileVersion}}, length, name -autosize
        }
        ElseIf($SCOMVersion -eq "7.1.10226.0")
        {
            $SCOMProductVersion = "SCOM 2012 R2"
            $URVersion  = Get-ChildItem -Path $SCOMFolder | where {$_.Name -eq "Csdal.dll"} | FT @{Label="FileVersion";Expression={$_.Versioninfo.FileVersion}}, length, name -autosize
        }
        Elseif ($SCOMVersion -eq "10.19.10050.0")
        {
            $SCOMProductVersion = "SCOM 2019"
            $URVersion  = Get-ChildItem -Path $SCOMFolder | where {$_.Name -eq "Csdal.dll"} | FT @{Label="FileVersion";Expression={$_.Versioninfo.FileVersion}}, length, name -autosize
        }
    
    
        Write-Log "Info" "Writing the Infra count.."
        #Creating a custom object to hold SCOM Infra Count details
        Write-Log "Info" "Creating a custom object to hold SCOM Count details"
        $Count = [PSCustomObject]@{
            ManagementServers   = $SCOMMS.count
            Gateway             = $Gateway.count
            WindowsComputer     = $Windowsagent.count
            UNIXAgent           = $SCXAgent.count
            NetworkDevice       = $NetworkDevice.count
            AgentlessComputer   = $agentlesscomputer.count
            ManagementPack      = $ManagementPacks.count
            Group               = $SCOMGroup.count
            PendingAgent        = $PendingAgent.count
            URLMonitoring       = $URLMonitoring.count
        }

        #Creating a custom object to hold SCOM Infra details
        Write-Log "Info" "Creating a custom object to hold SCOM Infra details"
        $Details = [PSCustomObject]@{
            ManagementServers   = $SCOMMS.displayname
            Gateway             = $Gateway.displayname
            WindowsComputer     = $Windowsagent.displayname
            UNIXAgent           = $SCXAgent.Name
            NetworkDevice       = $NetworkDevice.displayname
            AgentlessComputer   = $agentlesscomputer.displayname
            ManagementPack      = $ManagementPacks.displayname
            Group               = $SCOMGroup.displayname
            PendingAgent        = $PendingAgent.displayname
            URLMonitoring       = $URLMonitoring.displayname
        }

        #Writing the custom object to files
        Write-Log "Info" "Writing the custom object to files"
        $SCOMProductVersion | Out-File C:\Temp\SCOMLogs\SCOMInfra.txt
        $URVersion | Out-File C:\Temp\SCOMLogs\SCOMInfra.txt -Append
        $count | Out-File C:\Temp\SCOMLogs\SCOMInfra.txt -Append    
        $details | Select -ExpandProperty ManagementServers | Out-File  C:\Temp\SCOMLogs\SCOMMSDetails.txt
        $details | Select -ExpandProperty Gateway | Out-File C:\Temp\SCOMLogs\SCOMGatewayDetails.txt
        $details | Select -ExpandProperty WindowsComputer | Out-File C:\Temp\SCOMLogs\WindowsComputers.txt
        $details | Select -ExpandProperty UNIXAgent | Out-File C:\Temp\SCOMLogs\UNIXAgents.txt
        $details | Select -ExpandProperty NetworkDevice | Out-File C:\Temp\SCOMLogs\NetworkDevices.txt
        $details | Select -ExpandProperty AgentlessComputer | Out-File C:\Temp\SCOMLogs\AgentlessComputers.txt
        $details | Select -ExpandProperty ManagementPack | Out-File C:\Temp\SCOMLogs\ManagementPackDetails.txt
        $details | Select -ExpandProperty Group | Out-File C:\Temp\SCOMLogs\Groups.txt
        $details | Select -ExpandProperty PendingAgent | Out-File C:\Temp\SCOMLogs\PendingAgents.txt
        $details | Select -ExpandProperty URLMonitoring | Out-File C:\Temp\SCOMLogs\URLMonitoring.txt
        get-scomreportingsetting  | Out-File  C:\Temp\SCOMLogs\SCOMReportingDetails.txt
        Get-SCOMWebAddressSetting | Out-File  C:\Temp\SCOMLogs\SCOMWebConsoleDetails.txt
    }
    Catch
    {
        $ErrorMessage = $_.Exception.Message
        Write-Host "`nUnable to export SCOM Infra Details" -ForegroundColor Red
        $ErrorMessage        
        Write-Log "Error" "Unable to export SCOM Infra Details"
        $ErrorMessage | Out-File C:\Temp\SCOMLogs\SCOMLog_$($Date).txt -Append
        Exit
    }
}

Function Export-ResourcePoolMember(){
    Start-Sleep 2
    Try
    {
        Write-Host "`nExporting Resource Pool Membership.." -ForegroundColor Cyan
        Write-Log "Info" "Exporting Resource Pool Membership"
        $ResourcePools=Get-SCOMResourcePool  # -DisplayName "All Management Servers Resource Pool"
        foreach ($ResourcePool in $ResourcePools)
        {
            $members=$ResourcePool | Select Members
            $members1=$members.members
            $managementservers=$members1.displayname
            #Write-Host $ResourcePool.DisplayName -ForegroundColor Cyan
            $ResourcePool.DisplayName | Out-File C:\Temp\SCOMLogs\resourcepoolmembership.txt -Append
            $managementservers | Out-File C:\Temp\SCOMLogs\resourcepoolmembership.txt -Append        
        }
     }
     Catch
     {
        $ErrorMessage = $_.Exception.Message
        Write-Host "`nUnable to get Resource Pool details" -ForegroundColor Red
        $ErrorMessage        
        Write-Log "Error" "Unable to get Resource Pool details"
        $ErrorMessage | Out-File C:\Temp\SCOMLogs\SCOMLog_$($Date).txt -Append
        Exit
    }
}

Function Export-Registries(){
    Start-Sleep 2
    Write-Host "`nExporting SCOM related registries.." -ForegroundColor Cyan
    Try{
        Write-Log "Info" "Importing SCOM registry"
        New-Item -Path C:\Temp\SCOMLogs -Name Registries -ItemType Directory | Out-Null
        reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Operations Manager" "C:\Temp\SCOMLogs\Registries\MicrosoftOperatonsManager.reg" | Out-Null
        reg export "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HealthService" "C:\Temp\SCOMLogs\Registries\HealthService.reg" | Out-Null
        reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\System Center" "C:\Temp\SCOMLogs\Registries\SystemCenter.reg" | Out-Null
        reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\System Center Operations Manager" "C:\Temp\SCOMLogs\Registries\SystemCenterOperationsManager.reg" | Out-Null


        Write-Log "Info" "Importing SCHANNELProtocol registry"
        reg export "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" "C:\Temp\SCOMLogs\Registries\SCHANNELProtocol.reg" | Out-Null

        Write-Log "Info" "Importing StrongCrypto32bitDOTNET4 registry"
        reg export "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" "C:\Temp\SCOMLogs\Registries\StrongCrypto32bitDOTNET4.reg" | Out-Null

        Write-Log "Info" "Importing StrongCrypto64bitDOTNET4 registry"
        reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" "C:\Temp\SCOMLogs\Registries\StrongCrypto64bitDOTNET4.reg" | Out-Null
    }
    Catch
    {
        $ErrorMessage = $_.Exception.Message
        Write-Host "`nUnable to export registry" -ForegroundColor Red
        $ErrorMessage        
        Write-Log "Error" "Unable to export registry"
        $ErrorMessage | Out-File C:\Temp\SCOMLogs\SCOMLog_$($Date).txt -Append
        Exit
    }
}

Function Export-EventLogs(){
    Start-Sleep 2
    Try
    {
        Write-Host "`nExporting Event Logs.." -ForegroundColor Cyan
        Write-Log "Info" "Exporting event logs"

        $logFileNames=@('System', 'Application', 'Operations Manager')
        New-Item -Path C:\Temp\SCOMLogs -Name EventLogs -ItemType Directory | Out-Null

        foreach($logFileName in $logFileNames)
        {
        
            $path = "C:\Temp\SCOMLogs\EventLogs\" # Add Path, needs to end with a backsplash 
        
            $exportFileName = $logFileName + (get-date -f yyyyMMdd) + ".evt"
            $logFile = Get-WmiObject Win32_NTEventlogFile | Where-Object {$_.logfilename -eq $logFileName} 
            $logFile.backupeventlog($path + $exportFileName) | Out-Null
        }
    }
    Catch
    {
        $ErrorMessage = $_.Exception.Message
        Write-Host "`nUnable to export event logs" -ForegroundColor Red
        $ErrorMessage        
        Write-Log "Error" "Unable to export event logs"
        $ErrorMessage | Out-File C:\Temp\SCOMLogs\SCOMLog_$($Date).txt -Append
        Exit
    }
}

Function Compress-File(){
    Start-Sleep 2
    Write-Host "`nCompressing the data..." -ForegroundColor Cyan
    Try{
         Write-Log "Info" "Compressing the data"
         $hostname=hostname
         $path=Get-Item -Path C:\Temp\SCOMLogs_$($hostname).zip -ErrorAction SilentlyContinue
         If($path)
         {
            Write-Log "Info" "Removing old SCOM Logs Zipped file"
            Get-Item -Path C:\Temp\SCOMLogs_$($hostname).zip | Remove-Item -Force            
            Compress-Archive -Path C:\Temp\SCOMLogs -CompressionLevel Optimal -DestinationPath C:\Temp\SCOMLogs_$($hostname).zip
         }
         Else
         {
            Compress-Archive -Path C:\Temp\SCOMLogs -CompressionLevel Optimal -DestinationPath C:\Temp\SCOMLogs_$($hostname).zip
         }
    }
    Catch{
        $ErrorMessage = $_.Exception.Message
        Write-Host "`nUnable to compress data" -ForegroundColor Red
        $ErrorMessage        
        Write-Log "Error" "Unable to compress data"
        $ErrorMessage | Out-File C:\Temp\SCOMLogs\SCOMLog_$($Date).txt -Append
        Exit
    }   
    Write-Host "`nUpload or Send the folder C:\Temp\SCOMLogs_$($hostname).zip"-ForegroundColor Magenta
    
}

Function Main(){
    Check-IsAdministrator    
    Get-LogPath
    Install-Module
    Export-SystemData
    Export-SCOMInfraInfo
    Export-ResourcePoolMember
    Export-Registries
    Export-EventLogs
    Compress-File
}

#Calling Main
Main

Start-Sleep 2
Write-Host "`nScript ended.." -ForegroundColor Green
$sw.Stop()
Write-Host "`nTime to complele script (in seconds) : $($sw.Elapsed.Seconds)" -ForegroundColor Cyan
Write-Log "Info" "Time to complele script : $($sw.Elapsed.Seconds)"
