# Data_Collector
This is a repository for System Center Data Collector scripts

# SCOM Data Collector script

1. Once you download the script from the repository, copy it to any of the Management Server of the Management Group. Extract the zipped folder.
2. Make sure the folder C:\Temp is created.
3. Open a PowerShell.exe with an account which is SCOM Administrator and Local Administrator.
4. Navigate to the path where the script is copied and run it.

On Management Servers
.\SCOM_MS_DataCollector_v0.ps1 -IsManagementServer True

On Agents
.\SCOM_MS_DataCollector_v0.ps1 -IsManagementServer False

5. Once the script is complete a zipped file with all the data will be created in C:\Temp. Shared the data with Microsoft Support Professional.
