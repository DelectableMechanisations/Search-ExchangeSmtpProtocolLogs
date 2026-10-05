# Search Exchange SMTP Protocol Logs
A PowerShell workflow used to gather the SMTP Protocol logs from all Exchange Servers in an environment, and filter them using LogParser.exe.

Requires the following:
- ActiveDiretory PowerShell module (but not the Exchange Management Shell)
- LogParser.exe https://www.microsoft.com/en-us/download/details.aspx?id=24659
- Protocol Logging enabled on Receive Connectors