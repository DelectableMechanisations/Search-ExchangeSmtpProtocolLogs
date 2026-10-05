<#===============================================================================================================================================================================

Search-ExchangeServerSmtpLog

Only run one of the filters below, or if you want to combine 2 or more then create a brand new filter.
If you run one after the other it probably won't work.

===============================================================================================================================================================================#>

$LogParserPath        = 'C:\Program Files (x86)\Log Parser 2.2\LogParser.exe'
$LogParserStats       = 'Off'
$WorkingDirectoryRoot = "D:\Temp\ScriptWorkingDirectory"


<#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Functions

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------#>

Function Copy-ExchangeServerSmtpLogFiles {
    [CmdletBinding()]
    Param (
        [System.Decimal]
        $LogFileAge = 3,

        [Parameter(Mandatory)]
        [ValidateScript({(Test-Path -LiteralPath $_ -PathType Container -IsValid) -and (-not (Test-Path -LiteralPath $_))})]
        [System.String]
        $WorkingDirectory
    )
    New-Item -Path $WorkingDirectory -ItemType Directory -Force | Out-Null

    #Copy the recent Receive Protocol Logs from all Exchange Transport Servers into the local working directory.
    $transportServerLdapQuery = "(&(objectClass=msExchExchangeServer)(msExchTransportReceiveProtocolLogPath=*))"
    [Array]$transportServers = Get-ADObject -SearchBase (Get-ADRootDSE).configurationNamingContext -LDAPFilter $transportServerLdapQuery -Properties msExchTransportReceiveProtocolLogPath,networkAddress

    foreach ($transportServer in $transportServers) {
        $count = 1
        $exchangeServer = ($transportServer.networkAddress | Where-Object {$_ -like 'ncacn_ip_tcp:*'}).Split(':')[1]
        $exchangeServerReceiveProtocolLogPath = "\\$exchangeServer\$($transportServer.msExchTransportReceiveProtocolLogPath.Replace(':','$'))"
        Write-Verbose -Message "Processing Exchange Server $exchangeServer"

        #Identify all log files with a LastWriteTime less than $LogFileAge days old.
        [Array]$LogFiles = Get-ChildItem -Path $exchangeServerReceiveProtocolLogPath | Where-Object {$_.Length -gt 1 -and $_.LastWriteTime -gt (Get-Date).AddDays(-$LogFileAge)}
        Write-Verbose -Message "Identified $($LogFiles.Count) SMTP Receive Log file(s)"

        foreach ($LogFile in $LogFiles) {
            Write-Progress -Activity "Copying logs from $exchangeServer" -Status "$count of $($LogFiles.Count)" -PercentComplete (($count/$LogFiles.Count)*100) -CurrentOperation "$($LogFile.FullName)"
            Copy-Item -Path $LogFile.FullName -Destination "$WorkingDirectory\$($exchangeServer)_$($transportServer.Name)_$($LogFile.Name)"
            $count++
        }
    }
}

Function Export-ExchangeServerSmtpLogSearchResult {
    [CmdletBinding()]
    Param (
        [ValidateScript({Test-Path -LiteralPath $_ -PathType Leaf -IsValid})]
        [System.String]
        $FilePath,

        [ValidateScript({Test-Path -LiteralPath $_ -PathType Leaf})]
        [System.String]
        $LogParserPath = 'D:\Program Files (x86)\Log Parser 2.2\LogParser.exe',

        [ValidateSet('Off', 'On')]
        [System.String]
        $LogParserStats = 'Off',

        [System.String]
        $TempFileSuffix = '_FilteredResults.csv',

        [Parameter(Mandatory)]
        [ValidateScript({Test-Path -LiteralPath $_ -PathType Container})]
        [System.String]
        $WorkingDirectory
    )

    #Remove any CSV files with no content.
    Write-Verbose -Message "Remove empty files from '$WorkingDirectory' matching filter '*$TempFileSuffix'."
    $emptyCsvLogFiles = Get-ChildItem -Path $WorkingDirectory -Filter "*$TempFileSuffix"
    $emptyCsvLogFiles | Where-Object {$_.Length -eq 0} | Remove-Item

    #Execute Log Parser query to combine all the search result CSV files into 1 big CSV file.
    $searchQuery = @"
    SELECT
        TimeStamp,
        ReceiveConnector,
        SessionId,
        SequenceNumber,
        ServerIp,
        ServerPort,
        ClientIp,
        ClientPort,
        Event,
        Data,
        Context
    INTO '$FilePath'
    FROM '$WorkingDirectory\*$TempFileSuffix'
"@

    Write-Verbose -Message "Executing Log Parser query against '$WorkingDirectory' to combine all files matching filter '*$TempFileSuffix' into a single CSV file."
    & $LogParserPath -i:CSV -dtLines:100000 $searchQuery -stats:$LogParserStats

    #Remove any CSV files with no content.
    Write-Verbose -Message "Remove all remaining result files from '$WorkingDirectory' matching filter '*$TempFileSuffix'."
    Get-ChildItem -Path $WorkingDirectory -Filter "*$TempFileSuffix" | Remove-Item
}

Function Search-ExchangeServerSmtpLogByFullSmtpSession {
    Param (
        [ValidateScript({Test-Path -LiteralPath $_ -PathType Leaf})]
        [System.String]
        $LogParserPath = 'D:\Program Files (x86)\Log Parser 2.2\LogParser.exe',

        [ValidateSet('Off', 'On')]
        [System.String]
        $LogParserStats = 'Off',

        [System.String]
        $TempFileSuffix = '_Filtered_FullSmtpSessionsOnly.csv',

        [Parameter(Mandatory)]
        [ValidateScript({Test-Path -LiteralPath $_ -PathType Container})]
        [System.String]
        $WorkingDirectory
    )

    #Find all raw SMTP log files
    $smtpLogFiles = Get-ChildItem -Path $WorkingDirectory -Filter '*.log'

    $count = 1
    foreach ($smtpLogFile in $smtpLogFiles) {
        #Only show a progress update if the Log Parser Stats are switched off.
        if ($LogParserStats -eq 'Off') {
            Write-Progress -Activity "Searching SMTP log files for complete SMTP sessions" -Status "$count of $($smtpLogFiles.Count)" -PercentComplete (($count/$smtpLogFiles.Count)*100) -CurrentOperation "$($smtpLogFile.FullName)"
        }
        $tempFiltered_FullSmtpSessionsOnly   = "$WorkingDirectory\$($smtpLogFile.Name)$TempFileSuffix"

        <#Execute Log Parser query to filter out any SMTP sessions less than 8 lines of logs.
        Essentially it is not possible for a client to establish a session with Exchange and submit an
        email in less than 8 lines of logs so this filters out probes and load balancer monitors.#>
        $searchQuery = @"
            SELECT
                [#Fields: date-time]                         AS [TimeStamp],
                [connector-id]                               AS [ReceiveConnector],
                [session-id]                                 AS [SessionId],
                TO_INT([sequence-number])                    AS [SequenceNumber],
                EXTRACT_PREFIX([local-endpoint],0,':')       AS [ServerIp],
                EXTRACT_SUFFIX([local-endpoint],0,':')       AS [ServerPort],
                EXTRACT_PREFIX([remote-endpoint],0,':')      AS [ClientIp],
                EXTRACT_SUFFIX([remote-endpoint],0,':')      AS [ClientPort],
                event                                        AS [Event],
                data                                         AS [Data],
                context                                      AS [Context]
            INTO '$tempFiltered_FullSmtpSessionsOnly'
            FROM '$($smtpLogFile.FullName)'
            WHERE [session-id] IN (
                SELECT
                    [session-id]
                FROM '$($smtpLogFile.FullName)'
                WHERE [sequence-number] > 8
            )
"@
        & $LogParserPath -i:CSV -dtLines:100000 -nSkipLines:4 $SearchQuery -stats:$LogParserStats
        $count++
    }

    #Remove any csv files with no content.
    $emptyCsvLogFiles = Get-ChildItem -Path $WorkingDirectory -Filter "*$TempFileSuffix"
    $emptyCsvLogFiles | Where-Object {$_.Length -eq 0} | Remove-Item
}

Function Search-ExchangeServerSmtpLogByPort {
    Param (
        [ValidateScript({Test-Path -LiteralPath $_ -PathType Leaf})]
        [System.String]
        $LogParserPath = 'D:\Program Files (x86)\Log Parser 2.2\LogParser.exe',

        [ValidateSet('Off', 'On')]
        [System.String]
        $LogParserStats = 'Off',

        [Parameter(Mandatory)]
        [System.Int32]
        $Port,

        [System.String]
        $TempFileSuffix = '_FilteredResults.csv',

        [Parameter(Mandatory)]
        [ValidateScript({Test-Path -LiteralPath $_ -PathType Container})]
        [System.String]
        $WorkingDirectory
    )

    #Run the Search-ExchangeServerSmtpLogByFullSmtpSession function to pull out the Full SMTP Sessions first.
    $smtpCsvLogFileSuffix = '_Filtered_FullSmtpSessionsOnly.csv'
    $searchExchangeServerSmtpLogByFullSmtpSessionParameters = @{} + $PSBoundParameters
    $searchExchangeServerSmtpLogByFullSmtpSessionParameters.Remove('Port')
    $searchExchangeServerSmtpLogByFullSmtpSessionParameters['TempFileSuffix'] = $smtpCsvLogFileSuffix
    Search-ExchangeServerSmtpLogByFullSmtpSession @searchExchangeServerSmtpLogByFullSmtpSessionParameters

    [Array]$smtpCsvLogFiles = Get-ChildItem -Path $WorkingDirectory -Filter "*$smtpCsvLogFileSuffix"

    $count = 1
    foreach ($smtpCsvLogFile in $smtpCsvLogFiles) {
        Write-Progress -Activity "Searching SMTP CSV log files for sessions with a Port matching '$Port'." -Status "$count of $($smtpCsvLogFiles.Count)" -PercentComplete (($count/$smtpCsvLogFiles.Count)*100) -CurrentOperation "$($smtpCsvLogFile.FullName)"
        $tempFilteredResults = "$WorkingDirectory\$($smtpCsvLogFile.Name)$TempFileSuffix"

        $searchQuery = @"
            SELECT
                TimeStamp,
                ReceiveConnector,
                SessionId,
                SequenceNumber,
                ServerIp,
                ServerPort,
                ClientIp,
                ClientPort,
                Event,
                Data,
                Context
            INTO '$tempFilteredResults'
            FROM '$($smtpCsvLogFile.FullName)'
            WHERE ServerPort = '$Port'
"@
        & $LogParserPath -i:CSV -dtLines:100000 $searchQuery -stats:$LogParserStats
        $count++
    }

    #Remove any remaining temporary CSV files.
    Write-Verbose -Message "Remove all temporary SMTP CSV log files from '$WorkingDirectory' matching filter '*$smtpCsvLogFileSuffix'."
    Get-ChildItem -Path $WorkingDirectory -Filter "*$smtpCsvLogFileSuffix" | Remove-Item
}

Function Search-ExchangeServerSmtpLogBySessionsNotUsingTls {
    Param (
        [ValidateScript({Test-Path -LiteralPath $_ -PathType Leaf})]
        [System.String]
        $LogParserPath = 'D:\Program Files (x86)\Log Parser 2.2\LogParser.exe',

        [ValidateSet('Off', 'On')]
        [System.String]
        $LogParserStats = 'Off',

        [System.String]
        $TempFileSuffix = '_FilteredResults.csv',

        [Parameter(Mandatory)]
        [ValidateScript({Test-Path -LiteralPath $_ -PathType Container})]
        [System.String]
        $WorkingDirectory
    )

    #Run the Search-ExchangeServerSmtpLogByFullSmtpSession function to pull out the Full SMTP Sessions first.
    $smtpCsvLogFileSuffix = '_Filtered_FullSmtpSessionsOnly.csv'
    $searchExchangeServerSmtpLogByFullSmtpSessionParameters = @{} + $PSBoundParameters
    $searchExchangeServerSmtpLogByFullSmtpSessionParameters['TempFileSuffix'] = $smtpCsvLogFileSuffix
    Search-ExchangeServerSmtpLogByFullSmtpSession @searchExchangeServerSmtpLogByFullSmtpSessionParameters

    [Array]$smtpCsvLogFiles = Get-ChildItem -Path $WorkingDirectory -Filter "*$smtpCsvLogFileSuffix"

    $count = 1
    foreach ($smtpCsvLogFile in $smtpCsvLogFiles) {
        Write-Progress -Activity "Searching SMTP CSV log files for sessions not using TLS." -Status "$count of $($smtpCsvLogFiles.Count)" -PercentComplete (($count/$smtpCsvLogFiles.Count)*100) -CurrentOperation "$($smtpCsvLogFile.FullName)"
        $tempFilteredResults = "$WorkingDirectory\$($smtpCsvLogFile.Name)$TempFileSuffix"

        $searchQuery = @"
            SELECT
                TimeStamp,
                ReceiveConnector,
                SessionId,
                SequenceNumber,
                ServerIp,
                ServerPort,
                ClientIp,
                ClientPort,
                Event,
                Data,
                Context
            INTO '$tempFilteredResults'
            FROM '$($smtpCsvLogFile.FullName)'
            WHERE SessionId NOT IN (
                SELECT
                    SessionId
                FROM '$($smtpCsvLogFile.FullName)'
                WHERE Data = 'STARTTLS'
            )
"@
        & $LogParserPath -i:CSV -dtLines:100000 $searchQuery -stats:$LogParserStats
        $count++
    }

    #Remove any remaining temporary CSV files.
    Write-Verbose -Message "Remove all temporary SMTP CSV log files from '$WorkingDirectory' matching filter '*$smtpCsvLogFileSuffix'."
    Get-ChildItem -Path $WorkingDirectory -Filter "*$smtpCsvLogFileSuffix" | Remove-Item
}

Function Search-ExchangeServerSmtpLogByString {
    Param (
        [ValidateScript({Test-Path -LiteralPath $_ -PathType Leaf})]
        [System.String]
        $LogParserPath = 'D:\Program Files (x86)\Log Parser 2.2\LogParser.exe',

        [ValidateSet('Off', 'On')]
        [System.String]
        $LogParserStats = 'Off',

        [Parameter(Mandatory)]
        [System.String]
        $SearchString,

        [System.String]
        $TempFileSuffix = '_FilteredResults.csv',

        [Parameter(Mandatory)]
        [ValidateScript({Test-Path -LiteralPath $_ -PathType Container})]
        [System.String]
        $WorkingDirectory
    )

    $smtpLogFiles = Get-ChildItem -Path $WorkingDirectory -Filter '*.log'

    $count = 1
    foreach ($smtpLogFile in $smtpLogFiles) {
        #Only show a progress update if the Log Parser Stats are switched off.
        if ($LogParserStats -eq 'Off') {
            Write-Progress -Activity "Searching SMTP log files for sessions containing a string matching '$SearchString'." -Status "$count of $($smtpLogFiles.Count)" -PercentComplete (($count/$smtpLogFiles.Count)*100) -CurrentOperation "$($smtpLogFile.FullName)"
        }
        $tempFilteredResults = "$WorkingDirectory\$($smtpLogFile.Name)_FilteredResults.csv"

        $searchQuery = @"
            SELECT
                [#Fields: date-time]                         AS [TimeStamp],
                [connector-id]                               AS [ReceiveConnector],
                [session-id]                                 AS [SessionId],
                TO_INT([sequence-number])                    AS [SequenceNumber],
                EXTRACT_PREFIX([local-endpoint],0,':')       AS [ServerIp],
                EXTRACT_SUFFIX([local-endpoint],0,':')       AS [ServerPort],
                EXTRACT_PREFIX([remote-endpoint],0,':')      AS [ClientIp],
                EXTRACT_SUFFIX([remote-endpoint],0,':')      AS [ClientPort],
                event                                        AS [Event],
                data                                         AS [Data],
                context                                      AS [Context]
            INTO '$tempFilteredResults'
            FROM '$($smtpLogFile.FullName)'
            WHERE [session-id] IN (
                SELECT
                    [session-id]
                FROM '$($smtpLogFile.FullName)'
                WHERE data LIKE '%$SearchString%' OR context LIKE '%$SearchString%'
            )
"@
        & $LogParserPath -i:CSV -dtLines:100000 -nSkipLines:4 $SearchQuery -stats:$LogParserStats
        $count++
    }
}




<#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Script

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------#>

#Ask the user to select the Search Type.
Write-Host @"


Please choose the type of search you wish to perform:
    (1) String Search             - Use for searching for email addresses or server names in the EHLO message
    (2) All Anonymous Relay       - Use for exporting a list of all communications over port 25
    (3) All Authenticated Relay   - Use for exporting a list of all communications over port 587
    (4) All traffic not encrypted - Use for exporting a list of all communications that are not encrypted using STARTTLS

The default is '1'
"@ -ForegroundColor DarkGreen -BackgroundColor Black
[System.String]$userinput_SearchType = Read-Host ' '


#Ask the user to specify the maximum age of SMTP log files to search in days.
Write-Host @"
Please specify the maximum age of SMTP log files to search (days).

The default is '1'
"@ -ForegroundColor DarkGreen -BackgroundColor Black
try {
    [System.Decimal]$userinput_LogFileAge = Read-Host ' '
    if ($userinput_LogFileAge -eq 0) {$userinput_LogFileAge = 1}
} catch {
    throw "$_"
}

$startDate = Get-Date
$workingDirectory = "$WorkingDirectoryRoot\$($env:USERNAME)-$($startDate.ToString('yyyy-MM-dd HHmmss'))"

#Set the search parameters and variables.
$searchParameters = @{
    LogParserPath    = $LogParserPath
    LogParserStats   = $LogParserStats
    TempFileSuffix   = '_FilteredResults.csv'
    WorkingDirectory = $workingDirectory
}

switch ($userinput_SearchType) {
    #(2) All Anonymous Relay
    '2'     {
        $exportFilePath           = "$env:USERPROFILE\Desktop\$($startDate.ToString('yyyy-MM-dd HHmmss'))_SearchByPort25AnonymousRelay.csv"
        $searchCommand            = 'Search-ExchangeServerSmtpLogByPort'
        $searchParameters['Port'] = 25
        Break
    }

    #(3) All Authenticated Relay
    '3'     {
        $exportFilePath           = "$env:USERPROFILE\Desktop\$($startDate.ToString('yyyy-MM-dd HHmmss'))_SearchByPort587AuthenticatedRelay.csv"
        $searchCommand            = 'Search-ExchangeServerSmtpLogByPort'
        $searchParameters['Port'] = 587
        Break
    }

    #(4) All traffic not encrypted
    '4'     {
        $exportFilePath           = "$env:USERPROFILE\Desktop\$($startDate.ToString('yyyy-MM-dd HHmmss'))_SearchBySessionsNotUsingTls.csv"
        $searchCommand            = 'Search-ExchangeServerSmtpLogBySessionsNotUsingTls'
        Break
    }

    #(1) String Search (and everything else)
    Default {
        Write-Host @"
Please specify your search string (will search the 'data' field of the SMTP log files):
"@ -ForegroundColor DarkGreen -BackgroundColor Black
        [System.String]$userinput_SearchString = Read-Host ' '

        $exportFilePath                   = "$env:USERPROFILE\Desktop\$($startDate.ToString('yyyy-MM-dd HHmmss'))_SearchBySearchString.csv"
        $searchCommand                    = 'Search-ExchangeServerSmtpLogByString'
        $searchParameters['SearchString'] = $userinput_SearchString
    }
}

Write-Host "Starting $($startDate.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Yellow -BackgroundColor Black

#Copy the SMTP log files to the local working directory.
Copy-ExchangeServerSmtpLogFiles `
-LogFileAge       $userinput_LogFileAge `
-WorkingDirectory $workingDirectory `
-Verbose

#Search the SMTP log files using the specified parameters.
& $searchCommand @searchParameters

#Export the search results to a CSV file.
$exportParameters = @{
    FilePath         = $exportFilePath
    LogParserPath    = $LogParserPath
    LogParserStats   = $LogParserStats
    TempFileSuffix   = '_FilteredResults.csv'
    WorkingDirectory = $workingDirectory
}

Export-ExchangeServerSmtpLogSearchResult @exportParameters

Write-Host "Completed $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')."          -ForegroundColor Yellow -BackgroundColor Black
Write-Host "Time Taken: $(New-TimeSpan -Start $startDate -End (Get-Date))" -ForegroundColor Cyan   -BackgroundColor Black
Write-Host "Results output to: '$exportFilePath'"                          -ForegroundColor Green  -BackgroundColor Black

#Remove the contents of the working directory
Remove-Item -Path $workingDirectory -Force -Recurse