###################################################################################################################
######### This script will collect SCOM infrastrucutre details for Support Professional troubleshooting  ##########
#########                            Author: Udishman Mudiar (Udish)                                     ##########
#########                               Version 1.1                                                      ##########
###################################################################################################################
######################### Fixes ###################################################################################
##########              2/9/2020 - An unknown character was introduced in the line 244 and 382.         ###########
##########              Removed the trailing spacesand new lines                                        ###########
##########              2/9/2020 - The SCX agents were not outputted. Fixed the property to use Name ##############
###################################################################################################################
##########                              Revision in Version 1.1                                          ##########
##########                  Added a check if SDK is running. If not skip SCOM infra collection           ##########
##########                  Added option to use the script for in Management Server and in Agent         ##########
##########    Changed the name of the script to SCOM Infra Data Collector from SCOM MS Data Collector    ##########
#########                               Added workflow count details                                     ##########
#########                               Added hotfixes details                                           ##########
#########                               Included MP version                                              ##########
#########                               Added the Services details                                       ##########
#########                               Added the Processes details                                      ##########
###################################################################################################################



[CmdletBinding()]
param(
    [Parameter(Mandatory=$True)]
           [string]$IsManagementServer    
)

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
        hostname | Out-File C:\Temp\SCOMLogs\Hostname.txt
        Write-Log "Info" "Exported hostname"
        #Getting the ip details of the MS
        ipconfig /all | Out-File C:\Temp\SCOMLogs\IPConfig.txt
        Write-Log "Info" "Exported ip details"
        #Getting the system information of the MS
        systeminfo | Out-File C:\Temp\SCOMLogs\SystemInfo.txt
        Write-Log "Info" "Exported System Info"

        #exporting hotfixes
        Write-Host "`nExporting Hotfixes Info.." -ForegroundColor Cyan
        Write-Log "Info" "Exporting Hotfixes Info"
        Get-HotFix | Export-Csv -Path C:\Temp\SCOMLogs\Hotfixes.csv
            
        #Exporting Processes information
        Write-Host "`nExporting Processes Info.." -ForegroundColor Cyan
        Write-Log "Info" "Exporting Processes Info"
        Get-Process | Sort-Object -Property WS -Descending |  Format-Table `
            @{Label = "NPM(K)"; Expression = {[int]($_.NPM / 1024)}},
            @{Label = "PM(K)"; Expression = {[int]($_.PM / 1024)}},
            @{Label = "WS(K)"; Expression = {[int]($_.WS / 1024)}},
            @{Label = "VM(M)"; Expression = {[int]($_.VM / 1MB)}},
            @{Label = "CPU(s)"; Expression = {if ($_.CPU) {$_.CPU.ToString("N")}}},
            Id, MachineName, ProcessName -AutoSize  | Out-File  C:\Temp\SCOMLogs\Processes.txt

        #Exporting services information
        Write-Host "`nExporting Services Info.." -ForegroundColor Cyan
        Write-Log "Info" "Exporting Services Info"      
        Get-Service | Export-Csv -LiteralPath  C:\Temp\SCOMLogs\Services.csv
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

Function Export-SCOMMSInfraInfo(){

    Try
    {
        Start-Sleep 2
        #Checking if SCOM SDK is running. If NOT, then skip the SCOM infra collection
        Write-Host "`nChecking if SDK is running. If not skip SCOM infra collection" -ForegroundColor Cyan
        Write-Log "Info" "Checking if SDK is running. If not skip SCOM infra collection.."
        $SDKStatus=(Get-Service -Name OMSDK).Status

        if ($SDKStatus -eq "Running") {
            Write-Host "`nSDK is running. Continuing SCOM infra collection.." -ForegroundColor Green
            Write-Log "Info" "SDK is running. Continuing SCOM infra collection.."
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
             #writing workflow count of the health service
            $workflowcount= (Get-Counter -Counter '\Health Service\Workflow Count').countersamples.cookedvalue 
    
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
                Workflowcount       = $workflowcount
            }
    
            #Creating a custom object to hold SCOM Infra details
            Write-Log "Info" "Creating a custom object to hold SCOM Infra details"
            $Details = [PSCustomObject]@{
                ManagementServers   = $SCOMMS.displayname
                Gateway             = $Gateway.displayname
                WindowsComputer     = $Windowsagent.displayname
                UNIXAgent           = $SCXAgent.name
                NetworkDevice       = $NetworkDevice.displayname
                AgentlessComputer   = $agentlesscomputer.displayname
                #ManagementPack      = $ManagementPacks.displayname
                Group               = $SCOMGroup.displayname
                PendingAgent        = $PendingAgent.displayname
                URLMonitoring       = $URLMonitoring.displayname
                Workflowcount       = "WorkflowCount"
            }
    
            #Writing the custom object to files
            Write-Log "Info" "Writing the custom object to files"
            $SCOMProductVersion | Out-File C:\Temp\SCOMLogs\SCOMInfra.txt
            $URVersion | Out-File C:\Temp\SCOMLogs\SCOMInfra.txt -Append
            $count | Out-File C:\Temp\SCOMLogs\SCOMInfra.txt -Append    
            $details | Select-Object -ExpandProperty ManagementServers | Out-File  C:\Temp\SCOMLogs\SCOMMSDetails.txt
            $details | Select-Object -ExpandProperty Gateway | Out-File C:\Temp\SCOMLogs\SCOMGatewayDetails.txt
            $details | Select-Object -ExpandProperty WindowsComputer | Out-File C:\Temp\SCOMLogs\WindowsComputers.txt
            $details | Select-Object -ExpandProperty UNIXAgent | Out-File C:\Temp\SCOMLogs\UNIXAgents.txt
            $details | Select-Object -ExpandProperty NetworkDevice | Out-File C:\Temp\SCOMLogs\NetworkDevices.txt
            $details | Select-Object -ExpandProperty AgentlessComputer | Out-File C:\Temp\SCOMLogs\AgentlessComputers.txt            
            $details | Select-Object -ExpandProperty Group | Out-File C:\Temp\SCOMLogs\Groups.txt
            $details | Select-Object -ExpandProperty PendingAgent | Out-File C:\Temp\SCOMLogs\PendingAgents.txt
            $details | Select-Object -ExpandProperty URLMonitoring | Out-File C:\Temp\SCOMLogs\URLMonitoring.txt
            $ManagementPacks | Select-Object DisplayName,Name,Version | Export-Csv -LiteralPath C:\temp\SCOMLogs\ManagementPackDetails.csv
            get-scomreportingsetting  | Out-File  C:\Temp\SCOMLogs\SCOMReportingDetails.txt
            Get-SCOMWebAddressSetting | Out-File  C:\Temp\SCOMLogs\SCOMWebConsoleDetails.txt          
                     
            #Finally exporting the resource pool members by calling the function
            Export-ResourcePoolMember
        }
        else {
            Write-Host "`nSDK is NOT running. NOT proceeding SCOM infra collection" -ForegroundColor Red
            Write-Log "Error" "SDK is NOT running. NOT proceeding SCOM infra collection...."            
        }
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

function Export-SCOMAgentInfo () {
    #Collection info of SCOM Agent
    Write-Host "`nCollecing SCOM Agent Info Details.." -ForegroundColor Cyan
    Write-Log "Info" "Collecing SCOM Agent Info Details.."
    #writing workflow count of the health service
    (Get-Counter -Counter '\Health Service\Workflow Count').countersamples.cookedvalue | Out-File  C:\Temp\SCOMLogs\agentinfo.txt
}
Function Export-ResourcePoolMember(){
    Start-Sleep 2
    Try
    {
        Write-Host "`nExporting Resource Pool Membership.." -ForegroundColor Cyan
        Write-Log "Info" "Exporting Resource Pool Membership"
        $ResourcePools=Get-SCOMResourcePool
        foreach ($ResourcePool in $ResourcePools)
        {
            $members=$ResourcePool | Select Members
            $members1=$members.members
            $managementservers=$members1.displayname
            #Write-Host $ResourcePool.DisplayName -ForegroundColor Cyan
            $ResourcePool.DisplayName | Out-File C:\Temp\SCOMLogs\ResourcePoolMembership.txt -Append
            $managementservers | Out-File C:\Temp\SCOMLogs\ResourcePoolMembership.txt -Append        
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
        Write-Log "Info" "Exporting SCOM registry"
        New-Item -Path C:\Temp\SCOMLogs -Name Registries -ItemType Directory | Out-Null
        reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Operations Manager" "C:\Temp\SCOMLogs\Registries\MicrosoftOperatonsManager.reg" | Out-Null
        reg export "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HealthService" "C:\Temp\SCOMLogs\Registries\HealthService.reg" | Out-Null
        reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\System Center" "C:\Temp\SCOMLogs\Registries\SystemCenter.reg" | Out-Null
        reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\System Center Operations Manager" "C:\Temp\SCOMLogs\Registries\SystemCenterOperationsManager.reg" | Out-Null


        Write-Log "Info" "Exporting SCHANNELProtocol registry"
        reg export "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" "C:\Temp\SCOMLogs\Registries\SCHANNELProtocol.reg" | Out-Null

        Write-Log "Info" "Exporting StrongCrypto32bitDOTNET4 registry"
        reg export "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" "C:\Temp\SCOMLogs\Registries\StrongCrypto32bitDOTNET4.reg" | Out-Null

        Write-Log "Info" "Exporting StrongCrypto64bitDOTNET4 registry"
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
        
            $exportFileNameevt = $logFileName + (get-date -f yyyyMMdd) + ".evt"
            #$exportFileNamecsv = $logFileName + (get-date -f yyyyMMdd) + ".csv"
            $logFile = Get-WmiObject Win32_NTEventlogFile | Where-Object {$_.logfilename -eq $logFileName} 
            $logFile.backupeventlog($path + $exportFileNameevt) | Out-Null
            #Get-EventLog -LogName $logFileName | Export-Csv -LiteralPath $path\$exportFileNamecsv   
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
            Compress-Archive -Path C:\Temp\SCOMLogs -CompressionLevel Optimal -DestinationPath C:\Temp\SCOMLogs_$($hostname)_$($Date).zip
         }
         Else
         {
            Compress-Archive -Path C:\Temp\SCOMLogs -CompressionLevel Optimal -DestinationPath C:\Temp\SCOMLogs_$($hostname)_$($Date).zip            
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
    #As compressing is successful. Cleanig the logs folder.
    #Write-Host "`nCompressing successfull. Hence cleaning the logs folder..." -ForegroundColor Cyan
    #Write-Log "Info" "Removing SCOM Logs Folder as the compression is successful"
    #Remove-Item -Path C:\Temp\SCOMLogs -Recurse -Force -Confirm:$false
    Write-Host "`nUpload or Send the folder C:\Temp\SCOMLogs_$($hostname)_$($Date).zip"-ForegroundColor Magenta    
}
Function Main(){
    Check-IsAdministrator    
    Get-LogPath    
    If($IsManagementServer -eq "True")
    {
        Write-Host "`n This is choosen as a Management Server." -ForegroundColor Cyan
        Write-Log "Info" "This is choosen as a Management Server"
        Export-SystemData       
        Export-Registries
        Export-EventLogs
        Install-Module
        Export-SCOMMSInfraInfo
    }
    If($IsAgent -eq "True")
    {
        Write-Host "`n This is choosen as an Agent." -ForegroundColor Cyan
        Write-Log "Info" "This is choosen as an Agent"
        Export-SystemData       
        Export-Registries
        Export-EventLogs
        Export-SCOMAgentInfo   
    }
    Compress-File
}

#Calling Main
if ($IsManagementServer -eq "False"){
    #This is not a MS hence considering this as agent
    $IsAgent='True'
    Main
}
else {
    Main
}

Start-Sleep 2
Write-Host "`nScript ended.." -ForegroundColor Green
$sw.Stop()
Write-Host "`nTime to complele script (in seconds) : $($sw.Elapsed.Seconds)" -ForegroundColor Cyan
Write-Log "Info" "Time to complele script : $($sw.Elapsed.Seconds)"
