<# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
# Copyright (c) 2025 Global Micro Solutions (Pty) Ltd
# All rights reserved

.SYNOPSIS
    DLP Event Log Monitor - Windows Event Log analysis for DLP operational events.

.DESCRIPTION
    Comprehensive analysis of Windows Event Logs for Microsoft Purview Endpoint DLP operations.
    Monitors error rates, warning thresholds, policy synchronisation issues, and agent health
    to ensure optimal DLP deployment performance and reliability.

.PARAMETER Days
    Number of days to analyse in event logs (default: 7).

.PARAMETER IncludeDebugLogs
    Include debug-level events in analysis (may be verbose).

.PARAMETER ExportReports
    Export detailed CSV reports with event analysis and KPI tracking.

.PARAMETER QuickTest
    Run abbreviated analysis focusing on critical events only.

.PARAMETER ShowEventSamples
    Display sample events for each category found.

.WARRANTY
    Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
    either express or implied. See the Apache-2.0 WITH Commons-Clause License for the specific language
    governing permissions and limitations under the License.
#>

[CmdletBinding()]
param(
    [int]$Days = 7,
    [switch]$IncludeDebugLogs,
    [switch]$ExportReports,
    [switch]$QuickTest,
    [switch]$ShowEventSamples
)

$script:scriptVersion = "1.0"
$script:scriptAuthor = "JJ Milner"

# Color configuration
$Colors = @{
    Header = 'Cyan'
    Success = 'Green'
    Warning = 'Yellow'
    Error = 'Red'
    Info = 'White'
    Progress = 'Magenta'
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = 'White',
        [switch]$NoNewline
    )
    
    $params = @{
        Object = $Message
        ForegroundColor = $Color
    }
    
    if ($NoNewline) {
        $params.Add('NoNewline', $true)
    }
    
    Write-Host @params
}

# KPI Thresholds based on Microsoft guidance and enterprise standards
$EventLogKPIs = @{
    ErrorRate = 2.0                    # < 2% of DLP operations result in logged errors
    WarningThreshold = 10.0            # < 10% warning events per day
    PolicySyncFailures = 2.0           # < 2% policy synchronisation failures
    AgentHealthThreshold = 95.0        # > 95% agent availability and responsiveness
    CriticalEventThreshold = 0.5       # < 0.5% critical events per day
    ServiceRestartThreshold = 1.0      # < 1 service restart per day
}

Write-ColorOutput $('='*80) -Color $Colors.Header
Write-ColorOutput "DLP EVENT LOG MONITOR" -Color $Colors.Header
Write-ColorOutput "Version: $script:scriptVersion | Author: $script:scriptAuthor" -Color $Colors.Header
Write-ColorOutput $('='*80) -Color $Colors.Header

Write-ColorOutput "`nAnalysing Windows Event Logs for DLP operations over the last $Days days..." -Color $Colors.Info
Write-ColorOutput "KPI Thresholds:" -Color $Colors.Header
Write-ColorOutput "  Error Rate: < $($EventLogKPIs.ErrorRate)% of operations" -Color $Colors.Info
Write-ColorOutput "  Warning Events: < $($EventLogKPIs.WarningThreshold)% per day" -Color $Colors.Info
Write-ColorOutput "  Policy Sync Failures: < $($EventLogKPIs.PolicySyncFailures)%" -Color $Colors.Info
Write-ColorOutput "  Agent Health: > $($EventLogKPIs.AgentHealthThreshold)% availability" -Color $Colors.Info

function Test-DLPRelevance {
    param(
        [string]$EventSource,
        [int]$EventID,
        [string]$Message,
        [string]$ProviderName
    )
    
    # Define DLP-relevant criteria
    $dlpSources = @(
        "Microsoft-Windows-SENSE",
        "Microsoft-Windows-SenseNdr", 
        "Microsoft-Windows-Defender"
    )
    
    $dlpServices = @(
        "Windows Defender Advanced Threat Protection Service",
        "Windows Defender Service", 
        "Sense",
        "SenseNdr",
        "WinDefend",
        "MpDefenderCoreService",
        "MsSense"
    )
    
    $dlpKeywords = @(
        "Windows Defender Advanced Threat Protection",
        "Microsoft Defender for Endpoint",
        "DLP policy",
        "threat protection",
        "sense",
        "defender"
    )
    
    $nonDLPServices = @(
        "IntelTACD",
        "Dell TechHub", 
        "Dell Trusted Device",
        "Shell Hardware Detection",
        "SysMain",
        "Printer Extensions",
        "lmhosts"
    )
    
    # Check if explicitly non-DLP
    foreach ($nonDLPService in $nonDLPServices) {
        if ($Message -match [regex]::Escape($nonDLPService)) {
            return @{
                IsDLPRelevant = $false
                Category = "SystemMaintenance"
                Reason = "Non-DLP service: $nonDLPService"
            }
        }
    }
    
    # Check if DLP source
    if ($EventSource -in $dlpSources) {
        return @{
            IsDLPRelevant = $true
            Category = "DLPCore" 
            Reason = "DLP event source"
        }
    }
    
    # Check if DLP service mentioned
    foreach ($dlpService in $dlpServices) {
        if ($Message -match [regex]::Escape($dlpService)) {
            return @{
                IsDLPRelevant = $true
                Category = "DLPService"
                Reason = "DLP service: $dlpService"
            }
        }
    }
    
    # Check for DLP keywords
    foreach ($keyword in $dlpKeywords) {
        if ($Message -match [regex]::Escape($keyword)) {
            return @{
                IsDLPRelevant = $true
                Category = "DLPRelated"
                Reason = "DLP keyword: $keyword"
            }
        }
    }
    
    # Default to non-DLP
    return @{
        IsDLPRelevant = $false
        Category = "SystemGeneral"
        Reason = "No DLP indicators found"
    }
}

function Get-DetailedSystemErrors {
    param([datetime]$StartDate, [datetime]$EndDate)
    
    Write-ColorOutput "  Performing detailed System Event error analysis with DLP classification..." -Color $Colors.Progress
    
    try {
        # Get System errors related to DLP services
        $systemErrors = @(Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            Level = 2  # Error level
            StartTime = $StartDate
            EndTime = $EndDate
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.ProviderName -like "*Sense*" -or 
            $_.ProviderName -like "*Defender*" -or 
            $_.ProviderName -eq "Service Control Manager"
        })
        
        $errorDetails = @()
        $dlpErrorCount = 0
        $nonDlpErrorCount = 0
        
        foreach ($error in $systemErrors) {
            # Classify DLP relevance
            $dlpRelevance = Test-DLPRelevance -EventSource "System" -EventID $error.Id -Message $error.Message -ProviderName $error.ProviderName
            
            if ($dlpRelevance.IsDLPRelevant) {
                $dlpErrorCount++
            } else {
                $nonDlpErrorCount++
            }
            
            $errorDetails += [PSCustomObject]@{
                TimeCreated = $error.TimeCreated
                EventID = $error.Id
                Level = $error.LevelDisplayName
                Source = $error.ProviderName
                Message = $error.Message.Substring(0, [Math]::Min(500, $error.Message.Length))
                ProcessId = $error.ProcessId
                ThreadId = $error.ThreadId
                Keywords = $error.KeywordsDisplayNames -join "; "
                IsDLPRelevant = $dlpRelevance.IsDLPRelevant
                DLPCategory = $dlpRelevance.Category
                ClassificationReason = $dlpRelevance.Reason
            }
        }
        
        # Group by Event ID for analysis
        $groupedErrors = $systemErrors | Group-Object Id | Sort-Object Count -Descending
        $dlpGroupedErrors = $errorDetails | Where-Object { $_.IsDLPRelevant } | Group-Object EventID | Sort-Object Count -Descending
        $nonDlpGroupedErrors = $errorDetails | Where-Object { -not $_.IsDLPRelevant } | Group-Object EventID | Sort-Object Count -Descending
        
        Write-ColorOutput "    Found $($systemErrors.Count) total System errors" -Color $Colors.Info
        Write-ColorOutput "    DLP-related errors: $dlpErrorCount" -Color $(if ($dlpErrorCount -gt 0) { $Colors.Warning } else { $Colors.Success })
        Write-ColorOutput "    Non-DLP system errors: $nonDlpErrorCount" -Color $Colors.Info
        
        if ($dlpGroupedErrors.Count -gt 0) {
            Write-ColorOutput "    Top DLP-related System error IDs:" -Color $Colors.Info
            foreach ($group in ($dlpGroupedErrors | Select-Object -First 3)) {
                Write-ColorOutput "      ID $($group.Name): $($group.Count) occurrences" -Color $Colors.Info
            }
        }
        
        if ($nonDlpGroupedErrors.Count -gt 0) {
            Write-ColorOutput "    Top non-DLP System error IDs:" -Color $Colors.Info
            foreach ($group in ($nonDlpGroupedErrors | Select-Object -First 3)) {
                Write-ColorOutput "      ID $($group.Name): $($group.Count) occurrences (not DLP-related)" -Color $Colors.Info
            }
        }
        
        return @{
            TotalErrors = $systemErrors.Count
            DLPErrors = $dlpErrorCount
            NonDLPErrors = $nonDlpErrorCount
            ErrorDetails = $errorDetails
            GroupedErrors = $groupedErrors
            DLPGroupedErrors = $dlpGroupedErrors
            NonDLPGroupedErrors = $nonDlpGroupedErrors
        }
        
    } catch {
        Write-ColorOutput "    Error analysing System events: $($_.Exception.Message)" -Color $Colors.Warning
        return @{
            TotalErrors = 0
            DLPErrors = 0
            NonDLPErrors = 0
            ErrorDetails = @()
            GroupedErrors = @()
            DLPGroupedErrors = @()
            NonDLPGroupedErrors = @()
        }
    }
}

function Get-DetailedSenseErrors {
    param([datetime]$StartDate, [datetime]$EndDate)
    
    Write-ColorOutput "  Performing detailed Sense error analysis..." -Color $Colors.Progress
    
    try {
        # Check if Sense operational log exists
        $senseLogExists = Get-WinEvent -ListLog "Microsoft-Windows-Sense/Operational" -ErrorAction SilentlyContinue
        if (-not $senseLogExists) {
            Write-ColorOutput "    Microsoft-Windows-Sense/Operational log not available" -Color $Colors.Warning
            return @{ TotalErrors = 0; ErrorDetails = @(); GroupedErrors = @() }
        }
        
        # Get Sense errors
        $senseErrors = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Sense/Operational'
            Level = 2  # Error level
            StartTime = $StartDate
            EndTime = $EndDate
        } -ErrorAction SilentlyContinue)
        
        $errorDetails = @()
        foreach ($error in $senseErrors) {
            # Parse additional details from Sense events
            $eventData = $null
            if ($error.Message -match "ProcessId:\s*(\d+)") {
                $processId = $matches[1]
            }
            if ($error.Message -match "File:\s*([^\r\n]+)") {
                $fileName = $matches[1]
            }
            
            $errorDetails += [PSCustomObject]@{
                TimeCreated = $error.TimeCreated
                EventID = $error.Id
                Level = $error.LevelDisplayName
                Source = $error.ProviderName
                Message = $error.Message.Substring(0, [Math]::Min(500, $error.Message.Length))
                ProcessId = if ($processId) { $processId } else { $error.ProcessId }
                FileName = if ($fileName) { $fileName } else { "N/A" }
                Keywords = $error.KeywordsDisplayNames -join "; "
                Task = $error.TaskDisplayName
                Opcode = $error.OpcodeDisplayName
            }
        }
        
        # Group by Event ID
        $groupedErrors = $senseErrors | Group-Object Id | Sort-Object Count -Descending
        
        Write-ColorOutput "    Found $($senseErrors.Count) Sense errors" -Color $Colors.Info
        if ($groupedErrors.Count -gt 0) {
            Write-ColorOutput "    Top Sense error IDs:" -Color $Colors.Info
            foreach ($group in ($groupedErrors | Select-Object -First 5)) {
                Write-ColorOutput "      ID $($group.Name): $($group.Count) occurrences" -Color $Colors.Info
            }
        }
        
        return @{
            TotalErrors = $senseErrors.Count
            ErrorDetails = $errorDetails
            GroupedErrors = $groupedErrors
        }
        
    } catch {
        Write-ColorOutput "    Error analysing Sense events: $($_.Exception.Message)" -Color $Colors.Warning
        return @{
            TotalErrors = 0
            ErrorDetails = @()
            GroupedErrors = @()
        }
    }
}

function Get-AgentHealthDetails {
    param([datetime]$StartDate, [datetime]$EndDate)
    
    Write-ColorOutput "  Performing detailed agent health analysis..." -Color $Colors.Progress
    
    try {
        # Get agent health related events from multiple sources
        $healthEvents = @()
        
        # System events related to service health
        $systemHealthEvents = @(Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            StartTime = $StartDate
            EndTime = $EndDate
        } -ErrorAction SilentlyContinue | Where-Object {
            ($_.ProviderName -eq "Service Control Manager" -and 
             ($_.Message -match "Sense|Defender|MpDefender")) -or
            ($_.Id -in @(7034, 7031, 7036) -and 
             $_.Message -match "Sense|Defender|MpDefender")
        })
        
        # Application events related to agent health
        $appHealthEvents = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            StartTime = $StartDate
            EndTime = $EndDate
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.ProviderName -in @("MsSense", "SenseNdr", "MpDefenderCoreService") -and
            ($_.LevelDisplayName -in @("Error", "Warning") -and
             $_.Message -match "health|timeout|respond|communication|connection")
        })
        
        $allHealthEvents = $systemHealthEvents + $appHealthEvents
        
        $healthDetails = @()
        foreach ($event in $allHealthEvents) {
            $healthDetails += [PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                EventID = $event.Id
                Level = $event.LevelDisplayName
                Source = $event.ProviderName
                LogName = $event.LogName
                Message = $event.Message.Substring(0, [Math]::Min(300, $event.Message.Length))
                Category = if ($event.Message -match "start|stop|restart") { "Service" } 
                          elseif ($event.Message -match "timeout|respond|communication") { "Communication" }
                          elseif ($event.Message -match "health|status") { "Health" }
                          else { "Other" }
            }
        }
        
        # Calculate health metrics
        $serviceEvents = $healthDetails | Where-Object { $_.Category -eq "Service" }
        $communicationIssues = $healthDetails | Where-Object { $_.Category -eq "Communication" }
        $healthIssues = $healthDetails | Where-Object { $_.Category -eq "Health" }
        
        Write-ColorOutput "    Agent health events analysis:" -Color $Colors.Info
        Write-ColorOutput "      Service events: $($serviceEvents.Count)" -Color $Colors.Info
        Write-ColorOutput "      Communication issues: $($communicationIssues.Count)" -Color $Colors.Info
        Write-ColorOutput "      Health-specific issues: $($healthIssues.Count)" -Color $Colors.Info
        
        return @{
            TotalHealthEvents = $allHealthEvents.Count
            HealthDetails = $healthDetails
            ServiceEvents = $serviceEvents.Count
            CommunicationIssues = $communicationIssues.Count
            HealthIssues = $healthIssues.Count
        }
        
    } catch {
        Write-ColorOutput "    Error analysing agent health: $($_.Exception.Message)" -Color $Colors.Warning
        return @{
            TotalHealthEvents = 0
            HealthDetails = @()
            ServiceEvents = 0
            CommunicationIssues = 0
            HealthIssues = 0
        }
    }
}

function Get-PolicySyncAnalysis {
    param([datetime]$StartDate, [datetime]$EndDate)
    
    Write-ColorOutput "  Performing policy synchronisation analysis..." -Color $Colors.Progress
    
    try {
        # Search for policy-related events across all logs
        $policySyncEvents = @()
        
        # System events
        $systemPolicyEvents = @(Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            StartTime = $StartDate
            EndTime = $EndDate
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.Message -match "policy|sync|synchron|configuration|update" -and
            ($_.ProviderName -like "*Sense*" -or $_.ProviderName -like "*Defender*")
        })
        
        # Application events
        $appPolicyEvents = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            StartTime = $StartDate
            EndTime = $EndDate
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.ProviderName -in @("MsSense", "SenseNdr", "MpDefenderCoreService") -and
            $_.Message -match "policy|sync|synchron|configuration|update"
        })
        
        # Sense operational events
        $senseLogExists = Get-WinEvent -ListLog "Microsoft-Windows-Sense/Operational" -ErrorAction SilentlyContinue
        if ($senseLogExists) {
            $sensePolicyEvents = @(Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-Sense/Operational'
                StartTime = $StartDate
                EndTime = $EndDate
            } -ErrorAction SilentlyContinue | Where-Object {
                $_.Message -match "policy|sync|synchron|configuration|update"
            })
            $policySyncEvents += $sensePolicyEvents
        }
        
        $policySyncEvents += $systemPolicyEvents + $appPolicyEvents
        
        $policyDetails = @()
        foreach ($event in $policySyncEvents) {
            $syncStatus = "Unknown"
            if ($event.Message -match "success|successful|complete") { $syncStatus = "Success" }
            elseif ($event.Message -match "fail|error|timeout") { $syncStatus = "Failed" }
            elseif ($event.Message -match "start|begin|initiat") { $syncStatus = "Started" }
            
            $policyDetails += [PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                EventID = $event.Id
                Level = $event.LevelDisplayName
                Source = $event.ProviderName
                LogName = $event.LogName
                SyncStatus = $syncStatus
                Message = $event.Message.Substring(0, [Math]::Min(400, $event.Message.Length))
            }
        }
        
        # Calculate sync success rate
        $totalSyncEvents = $policyDetails.Count
        $failedSyncs = ($policyDetails | Where-Object { $_.SyncStatus -eq "Failed" }).Count
        $successfulSyncs = ($policyDetails | Where-Object { $_.SyncStatus -eq "Success" }).Count
        
        $syncSuccessRate = if ($totalSyncEvents -gt 0) { 
            [math]::Round(($successfulSyncs / $totalSyncEvents) * 100, 2) 
        } else { 100 }
        
        Write-ColorOutput "    Policy sync analysis results:" -Color $Colors.Info
        Write-ColorOutput "      Total policy events: $totalSyncEvents" -Color $Colors.Info
        Write-ColorOutput "      Successful syncs: $successfulSyncs" -Color $Colors.Info
        Write-ColorOutput "      Failed syncs: $failedSyncs" -Color $Colors.Info
        Write-ColorOutput "      Success rate: $syncSuccessRate%" -Color $Colors.Info
        
        return @{
            TotalPolicyEvents = $totalSyncEvents
            PolicyDetails = $policyDetails
            FailedSyncs = $failedSyncs
            SuccessfulSyncs = $successfulSyncs
            SyncSuccessRate = $syncSuccessRate
        }
        
    } catch {
        Write-ColorOutput "    Error analysing policy sync: $($_.Exception.Message)" -Color $Colors.Warning
        return @{
            TotalPolicyEvents = 0
            PolicyDetails = @()
            FailedSyncs = 0
            SuccessfulSyncs = 0
            SyncSuccessRate = 100
        }
    }
}

function Get-DLPErrorTypeAnalysis {
    param(
        $DetailedSenseErrors,
        $DetailedSystemErrors,
        [int]$Days
    )
    
    Write-ColorOutput "  Performing comprehensive DLP error type analysis..." -Color $Colors.Progress
    
    $errorAnalysis = @{
        SenseErrorAnalysis = @{}
        SystemDLPErrorAnalysis = @{}
        OverallImpact = @{}
        Recommendations = @()
    }
    
    # Analyze Sense errors by Event ID
    if ($DetailedSenseErrors.TotalErrors -gt 0) {
        foreach ($group in $DetailedSenseErrors.GroupedErrors) {
            $eventId = $group.Name
            $count = $group.Count
            $frequency = [math]::Round($count / $Days, 2)
            
            $analysis = switch ($eventId) {
                "101" {
                    @{
                        Description = "Network Detection & Response Startup Failure"
                        Severity = if ($count -gt 20) { "High" } elseif ($count -gt 10) { "Medium" } else { "Low" }
                        Impact = "NDR component fails to initialize - affects advanced threat detection capabilities"
                        Causes = @(
                            "System resource constraints during startup",
                            "Service dependency timing issues", 
                            "Corrupt NDR component files",
                            "Insufficient system privileges"
                        )
                        Actions = @(
                            "Check system resource utilization during startup",
                            "Verify service dependencies are running",
                            "Consider delaying NDR startup after system boot",
                            "Review system event logs for related hardware issues"
                        )
                        BusinessImpact = "Minor - NDR retries automatically, DLP functionality continues"
                    }
                }
                "405" {
                    @{
                        Description = "Authentication Service Communication Failure"
                        Severity = if ($count -gt 15) { "High" } elseif ($count -gt 5) { "Medium" } else { "Low" }
                        Impact = "Cannot authenticate with Microsoft cloud services - affects policy updates and telemetry"
                        Causes = @(
                            "DNS resolution failures for Microsoft ATP services",
                            "Network connectivity issues", 
                            "Proxy/firewall blocking Microsoft endpoints",
                            "System time synchronization problems"
                        )
                        Actions = @(
                            "Verify DNS resolution for *.securitycenter.windows.com",
                            "Test network connectivity to Microsoft ATP endpoints",
                            "Review proxy/firewall logs for blocked connections",
                            "Check system time synchronization with time.windows.com"
                        )
                        BusinessImpact = "Medium - May delay policy updates and reduce telemetry visibility"
                    }
                }
                "100" {
                    @{
                        Description = "Service Initialization Error"
                        Severity = "High"
                        Impact = "Core service cannot start - significant DLP functionality impairment"
                        Causes = @("Service configuration corruption", "Missing dependencies", "Permission issues")
                        Actions = @("Restart Windows Defender ATP service", "Check service configuration", "Verify system permissions")
                        BusinessImpact = "High - Core DLP functionality affected"
                    }
                }
                default {
                    @{
                        Description = "Unknown Sense Error (Event ID $eventId)"
                        Severity = "Medium"
                        Impact = "Unclassified Microsoft Defender for Endpoint error"
                        Causes = @("Requires investigation")
                        Actions = @("Review Microsoft documentation for Event ID $eventId", "Check with Microsoft Support")
                        BusinessImpact = "Unknown - requires investigation"
                    }
                }
            }
            
            $analysis.Count = $count
            $analysis.FrequencyPerDay = $frequency
            $analysis.EventID = $eventId
            
            $errorAnalysis.SenseErrorAnalysis[$eventId] = $analysis
        }
    }
    
    # Analyze System DLP errors by Event ID
    if ($DetailedSystemErrors.DLPErrors -gt 0) {
        foreach ($group in $DetailedSystemErrors.DLPGroupedErrors) {
            $eventId = $group.Name
            $count = $group.Count
            $frequency = [math]::Round($count / $Days, 2)
            
            $analysis = switch ($eventId) {
                "7043" {
                    @{
                        Description = "Windows Defender ATP Service Shutdown Issue"
                        Severity = "Low"
                        Impact = "Service does not shut down cleanly during system restart/shutdown"
                        Causes = @(
                            "Service taking longer than expected to clean up resources",
                            "System shutdown timing too aggressive",
                            "Pending operations during shutdown"
                        )
                        Actions = @(
                            "Monitor if this affects system restart times",
                            "Check if pattern correlates with system performance issues",
                            "Consider adjusting service shutdown timeout if problematic"
                        )
                        BusinessImpact = "Minimal - Service restarts cleanly, no functional impact"
                    }
                }
                "7034" {
                    @{
                        Description = "DLP Service Unexpected Termination"
                        Severity = "High"
                        Impact = "DLP service crashed unexpectedly - temporary loss of protection"
                        Causes = @("Memory issues", "Service corruption", "System instability")
                        Actions = @("Investigate crash dumps", "Check system stability", "Monitor service recovery")
                        BusinessImpact = "High - Temporary loss of DLP protection until service restarts"
                    }
                }
                "7000" {
                    @{
                        Description = "DLP Service Failed to Start"
                        Severity = "Critical"
                        Impact = "DLP service cannot start - no DLP protection active"
                        Causes = @("Missing service files", "Configuration issues", "Dependency failures")
                        Actions = @("Check service configuration", "Verify file integrity", "Review dependencies")
                        BusinessImpact = "Critical - No DLP protection until resolved"
                    }
                }
                default {
                    @{
                        Description = "Unknown System DLP Error (Event ID $eventId)"
                        Severity = "Medium"
                        Impact = "Unclassified system-level DLP service error"
                        Causes = @("Requires investigation")
                        Actions = @("Review system event details", "Check service status")
                        BusinessImpact = "Unknown - requires investigation"
                    }
                }
            }
            
            $analysis.Count = $count
            $analysis.FrequencyPerDay = $frequency
            $analysis.EventID = $eventId
            
            $errorAnalysis.SystemDLPErrorAnalysis[$eventId] = $analysis
        }
    }
    
    # Overall impact assessment
    $totalDLPErrors = $DetailedSenseErrors.TotalErrors + $DetailedSystemErrors.DLPErrors
    $criticalErrors = 0
    $highSeverityErrors = 0
    $mediumSeverityErrors = 0
    $lowSeverityErrors = 0
    
    foreach ($analysis in $errorAnalysis.SenseErrorAnalysis.Values) {
        switch ($analysis.Severity) {
            "Critical" { $criticalErrors += $analysis.Count }
            "High" { $highSeverityErrors += $analysis.Count }
            "Medium" { $mediumSeverityErrors += $analysis.Count }
            "Low" { $lowSeverityErrors += $analysis.Count }
        }
    }
    
    foreach ($analysis in $errorAnalysis.SystemDLPErrorAnalysis.Values) {
        switch ($analysis.Severity) {
            "Critical" { $criticalErrors += $analysis.Count }
            "High" { $highSeverityErrors += $analysis.Count }
            "Medium" { $mediumSeverityErrors += $analysis.Count }
            "Low" { $lowSeverityErrors += $analysis.Count }
        }
    }
    
    $errorAnalysis.OverallImpact = @{
        TotalDLPErrors = $totalDLPErrors
        CriticalErrors = $criticalErrors
        HighSeverityErrors = $highSeverityErrors
        MediumSeverityErrors = $mediumSeverityErrors
        LowSeverityErrors = $lowSeverityErrors
        PrimaryRiskLevel = if ($criticalErrors -gt 0) { "Critical" } 
                          elseif ($highSeverityErrors -gt 5) { "High" }
                          elseif ($mediumSeverityErrors -gt 10) { "Medium" } 
                          else { "Low" }
    }
    
    # Generate prioritized recommendations
    $recommendations = @()
    
    # Priority 1: Critical and High severity errors
    foreach ($eventId in $errorAnalysis.SenseErrorAnalysis.Keys) {
        $analysis = $errorAnalysis.SenseErrorAnalysis[$eventId]
        if ($analysis.Severity -in @("Critical", "High")) {
            $recommendations += @{
                Priority = 1
                Category = "Sense Service"
                EventID = $eventId
                Issue = $analysis.Description
                Actions = $analysis.Actions
                BusinessImpact = $analysis.BusinessImpact
            }
        }
    }
    
    foreach ($eventId in $errorAnalysis.SystemDLPErrorAnalysis.Keys) {
        $analysis = $errorAnalysis.SystemDLPErrorAnalysis[$eventId]
        if ($analysis.Severity -in @("Critical", "High")) {
            $recommendations += @{
                Priority = 1
                Category = "System DLP Service"
                EventID = $eventId
                Issue = $analysis.Description
                Actions = $analysis.Actions
                BusinessImpact = $analysis.BusinessImpact
            }
        }
    }
    
    # Priority 2: Medium severity errors with high frequency
    foreach ($eventId in $errorAnalysis.SenseErrorAnalysis.Keys) {
        $analysis = $errorAnalysis.SenseErrorAnalysis[$eventId]
        if ($analysis.Severity -eq "Medium" -and $analysis.FrequencyPerDay -gt 2) {
            $recommendations += @{
                Priority = 2
                Category = "Sense Service"
                EventID = $eventId
                Issue = $analysis.Description
                Actions = $analysis.Actions
                BusinessImpact = $analysis.BusinessImpact
            }
        }
    }
    
    $errorAnalysis.Recommendations = $recommendations
    
    return $errorAnalysis
}
$DLPEventSources = @{
    "Microsoft-Windows-Sense" = @{
        LogName = "Microsoft-Windows-Sense/Operational"
        Description = "Microsoft Defender for Endpoint"
        CriticalIDs = @(1001, 1002, 1010)
        ErrorIDs = @(2001, 2002, 2010, 2020)
        WarningIDs = @(3001, 3002, 3010)
        InfoIDs = @(4001, 4002, 4010, 4020)
    }
    "Microsoft-Windows-SenseNdr" = @{
        LogName = "Microsoft-Windows-SenseNdr/Operational"
        Description = "Sense Network Detection and Response"
        CriticalIDs = @(100, 101)
        ErrorIDs = @(200, 201, 202)
        WarningIDs = @(300, 301)
        InfoIDs = @(400, 401, 402)
    }
    "Microsoft-Windows-Defender" = @{
        LogName = "Microsoft-Windows-Windows Defender/Operational"
        Description = "Windows Defender"
        CriticalIDs = @(1000, 1001)
        ErrorIDs = @(2000, 2001, 2010)
        WarningIDs = @(3000, 3001)
        InfoIDs = @(5000, 5001, 5010)
    }
    "Application" = @{
        LogName = "Application"
        Description = "Application Events"
        CriticalIDs = @()
        ErrorIDs = @()
        WarningIDs = @()
        InfoIDs = @()
        SourceFilter = @("MsSense", "SenseNdr", "MpDefenderCoreService", "MSSENSE")
    }
    "System" = @{
        LogName = "System"
        Description = "System Events"
        CriticalIDs = @(7034, 7031)  # Service crashes
        ErrorIDs = @(7000, 7001, 7023, 7024)
        WarningIDs = @(7011, 7026)
        InfoIDs = @(7036)  # Service started/stopped
        SourceFilter = @("Service Control Manager")
        ServiceFilter = @("Sense", "WinDefend", "MpDefenderCoreService")
    }
}

try {
    Write-ColorOutput "`nInitialising event log analysis..." -Color $Colors.Progress
    
    $startDate = (Get-Date).AddDays(-$Days)
    $endDate = Get-Date
    
    $eventAnalysis = @{
        TotalEvents = 0
        CriticalEvents = 0
        ErrorEvents = 0
        WarningEvents = 0
        InfoEvents = 0
        EventsBySource = @{}
        EventsByDay = @{}
        ServiceEvents = @{}
        PolicySyncEvents = @{}
        AgentHealthEvents = @{}
        SampleEvents = @{}
    }
    
    $allEvents = @()
    $sourceAnalysisResults = @{}
    
    Write-ColorOutput "`nAnalysing DLP event sources..." -Color $Colors.Progress
    
    foreach ($sourceName in $DLPEventSources.Keys) {
        $source = $DLPEventSources[$sourceName]
        $sourceEvents = @()
        
        Write-ColorOutput "  Processing $sourceName ($($source.Description))..." -Color $Colors.Info
        
        try {
            # Check if event log exists
            $logExists = Get-WinEvent -ListLog $source.LogName -ErrorAction SilentlyContinue
            if (-not $logExists) {
                Write-ColorOutput "    [SKIP] Log $($source.LogName) not available" -Color $Colors.Warning
                continue
            }
            
            # Build filter hashtable
            $filterHashtable = @{
                LogName = $source.LogName
                StartTime = $startDate
                EndTime = $endDate
            }
            
            # Add source filter for generic logs
            if ($source.SourceFilter) {
                $events = @()
                foreach ($sourceFilter in $source.SourceFilter) {
                    try {
                        $filterHashtable.ProviderName = $sourceFilter
                        $sourceEvents = @(Get-WinEvent -FilterHashtable $filterHashtable -ErrorAction SilentlyContinue)
                        if ($sourceEvents.Count -gt 0) {
                            $events += $sourceEvents
                        }
                    } catch {
                        # Source not found, continue
                    }
                }
                $sourceEvents = $events
            } else {
                $sourceEvents = @(Get-WinEvent -FilterHashtable $filterHashtable -ErrorAction SilentlyContinue)
            }
            
            Write-ColorOutput "    Found $($sourceEvents.Count) events" -Color $(if ($sourceEvents.Count -gt 0) { $Colors.Success } else { $Colors.Info })
            
            if ($sourceEvents.Count -gt 0) {
                $allEvents += $sourceEvents
                
                # Categorise events
                $sourceAnalysis = @{
                    Source = $sourceName
                    Description = $source.Description
                    TotalEvents = $sourceEvents.Count
                    CriticalEvents = 0
                    ErrorEvents = 0
                    WarningEvents = 0
                    InfoEvents = 0
                    ServiceRestarts = 0
                    PolicySyncIssues = 0
                    AgentHealthIssues = 0
                    SampleEvents = @()
                }
                
                foreach ($event in $sourceEvents) {
                    $eventDate = $event.TimeCreated.Date.ToString('yyyy-MM-dd')
                    
                    if (-not $eventAnalysis.EventsByDay.ContainsKey($eventDate)) {
                        $eventAnalysis.EventsByDay[$eventDate] = 0
                    }
                    $eventAnalysis.EventsByDay[$eventDate]++
                    
                    # Categorise by level
                    switch ($event.LevelDisplayName) {
                        "Critical" { 
                            $sourceAnalysis.CriticalEvents++
                            $eventAnalysis.CriticalEvents++
                        }
                        "Error" { 
                            $sourceAnalysis.ErrorEvents++
                            $eventAnalysis.ErrorEvents++
                        }
                        "Warning" { 
                            $sourceAnalysis.WarningEvents++
                            $eventAnalysis.WarningEvents++
                        }
                        default { 
                            $sourceAnalysis.InfoEvents++
                            $eventAnalysis.InfoEvents++
                        }
                    }
                    
                    # Analyse specific event types
                    if ($event.Id -in $source.CriticalIDs -or $event.LevelDisplayName -eq "Critical") {
                        $sourceAnalysis.CriticalEvents++
                    }
                    
                    # Service restart detection
                    if ($sourceName -eq "System" -and $event.Id -eq 7036) {
                        $message = $event.Message
                        foreach ($service in $source.ServiceFilter) {
                            if ($message -match $service -and $message -match "stopped|started") {
                                $sourceAnalysis.ServiceRestarts++
                                break
                            }
                        }
                    }
                    
                    # Policy sync issue detection
                    if ($event.Message -match "policy|sync|synchron" -and $event.LevelDisplayName -in @("Error", "Warning")) {
                        $sourceAnalysis.PolicySyncIssues++
                    }
                    
                    # Agent health issue detection
                    if ($event.Message -match "agent|health|respond|timeout" -and $event.LevelDisplayName -in @("Error", "Critical")) {
                        $sourceAnalysis.AgentHealthIssues++
                    }
                    
                    # Collect sample events
                    if ($ShowEventSamples -and $sourceAnalysis.SampleEvents.Count -lt 3) {
                        $sourceAnalysis.SampleEvents += @{
                            Time = $event.TimeCreated
                            Level = $event.LevelDisplayName
                            ID = $event.Id
                            Message = $event.Message.Substring(0, [Math]::Min(100, $event.Message.Length))
                        }
                    }
                }
                
                $sourceAnalysisResults[$sourceName] = $sourceAnalysis
            }
            
        } catch {
            Write-ColorOutput "    [!] Error analysing $sourceName`: $($_.Exception.Message)" -Color $Colors.Warning
        }
    }
    
    $eventAnalysis.TotalEvents = $allEvents.Count
    
    # Perform detailed analysis of error sources
    Write-ColorOutput "`nPerforming detailed error analysis..." -Color $Colors.Progress
    
    $detailedSystemErrors = Get-DetailedSystemErrors -StartDate $startDate -EndDate $endDate
    $detailedSenseErrors = Get-DetailedSenseErrors -StartDate $startDate -EndDate $endDate
    $agentHealthAnalysis = Get-AgentHealthDetails -StartDate $startDate -EndDate $endDate
    $policySyncAnalysis = Get-PolicySyncAnalysis -StartDate $startDate -EndDate $endDate
    $dlpErrorTypeAnalysis = Get-DLPErrorTypeAnalysis -DetailedSenseErrors $detailedSenseErrors -DetailedSystemErrors $detailedSystemErrors -Days $Days
    
    # Store detailed results for reporting
    $eventAnalysis.DetailedSystemErrors = $detailedSystemErrors
    $eventAnalysis.DetailedSenseErrors = $detailedSenseErrors
    $eventAnalysis.AgentHealthAnalysis = $agentHealthAnalysis
    $eventAnalysis.PolicySyncAnalysis = $policySyncAnalysis
    $eventAnalysis.DLPErrorTypeAnalysis = $dlpErrorTypeAnalysis
    
    Write-ColorOutput "`n" + $('='*60) -Color $Colors.Header
    Write-ColorOutput "EVENT LOG ANALYSIS RESULTS" -Color $Colors.Header
    Write-ColorOutput $('='*60) -Color $Colors.Header
    
    if ($eventAnalysis.TotalEvents -gt 0) {
        Write-ColorOutput "`nEvent Summary (Last $Days days):" -Color $Colors.Header
        Write-ColorOutput "  Total Events: $($eventAnalysis.TotalEvents)" -Color $Colors.Info
        Write-ColorOutput "  Critical Events: $($eventAnalysis.CriticalEvents)" -Color $(if ($eventAnalysis.CriticalEvents -gt 0) { $Colors.Error } else { $Colors.Success })
        Write-ColorOutput "  Error Events: $($eventAnalysis.ErrorEvents)" -Color $(if ($eventAnalysis.ErrorEvents -gt 0) { $Colors.Error } else { $Colors.Success })
        Write-ColorOutput "  Warning Events: $($eventAnalysis.WarningEvents)" -Color $(if ($eventAnalysis.WarningEvents -gt 0) { $Colors.Warning } else { $Colors.Success })
        Write-ColorOutput "  Info Events: $($eventAnalysis.InfoEvents)" -Color $Colors.Info
        
        # Daily event distribution
        if ($eventAnalysis.EventsByDay.Count -gt 0) {
            Write-ColorOutput "`nDaily Event Distribution:" -Color $Colors.Header
            $sortedDays = $eventAnalysis.EventsByDay.Keys | Sort-Object
            foreach ($day in $sortedDays) {
                $count = $eventAnalysis.EventsByDay[$day]
                Write-ColorOutput "  $day`: $count events" -Color $Colors.Info
            }
        }
        
        # Source breakdown
        Write-ColorOutput "`nEvent Source Analysis:" -Color $Colors.Header
        foreach ($sourceName in $sourceAnalysisResults.Keys) {
            $analysis = $sourceAnalysisResults[$sourceName]
            Write-ColorOutput "  $sourceName ($($analysis.Description)):" -Color $Colors.Info
            Write-ColorOutput "    Total: $($analysis.TotalEvents) events" -Color $Colors.Info
            Write-ColorOutput "    Critical: $($analysis.CriticalEvents)" -Color $(if ($analysis.CriticalEvents -gt 0) { $Colors.Error } else { $Colors.Success })
            Write-ColorOutput "    Errors: $($analysis.ErrorEvents)" -Color $(if ($analysis.ErrorEvents -gt 0) { $Colors.Error } else { $Colors.Success })
            Write-ColorOutput "    Warnings: $($analysis.WarningEvents)" -Color $(if ($analysis.WarningEvents -gt 0) { $Colors.Warning } else { $Colors.Success })
            Write-ColorOutput "    Service Issues: $($analysis.ServiceRestarts)" -Color $(if ($analysis.ServiceRestarts -gt 0) { $Colors.Warning } else { $Colors.Success })
            Write-ColorOutput "    Policy Sync Issues: $($analysis.PolicySyncIssues)" -Color $(if ($analysis.PolicySyncIssues -gt 0) { $Colors.Error } else { $Colors.Success })
            Write-ColorOutput "    Agent Health Issues: $($analysis.AgentHealthIssues)" -Color $(if ($analysis.AgentHealthIssues -gt 0) { $Colors.Error } else { $Colors.Success })
            
            if ($ShowEventSamples -and $analysis.SampleEvents.Count -gt 0) {
                Write-ColorOutput "    Sample Events:" -Color $Colors.Info
                foreach ($sample in $analysis.SampleEvents) {
                    Write-ColorOutput "      $($sample.Time.ToString('MM/dd HH:mm')) [$($sample.Level)] ID:$($sample.ID) - $($sample.Message)..." -Color $Colors.Info
                }
            }
        }
        
        # KPI Assessment
        Write-ColorOutput "`n" + $('='*60) -Color $Colors.Header
        Write-ColorOutput "KPI ASSESSMENT" -Color $Colors.Header
        Write-ColorOutput $('='*60) -Color $Colors.Header
        
        # KPI Assessment with DLP-focused calculations
        Write-ColorOutput "`n" + $('='*60) -Color $Colors.Header
        Write-ColorOutput "DLP-FOCUSED KPI ASSESSMENT" -Color $Colors.Header
        Write-ColorOutput $('='*60) -Color $Colors.Header
        
        # Calculate DLP-specific metrics
        $totalDLPEvents = $eventAnalysis.TotalEvents
        $dlpCriticalEvents = $eventAnalysis.CriticalEvents  # All critical events from DLP sources
        $dlpErrorEvents = ($detailedSystemErrors.DLPErrors + $detailedSenseErrors.TotalErrors)  # Only DLP-related errors
        $nonDlpErrorEvents = $detailedSystemErrors.NonDLPErrors
        
        # Calculate DLP error rates (focused calculation)
        $dlpErrorRate = if ($totalDLPEvents -gt 0) { [math]::Round($dlpErrorEvents / $totalDLPEvents * 100, 2) } else { 0 }
        $totalSystemErrorRate = if ($totalDLPEvents -gt 0) { [math]::Round(($dlpErrorEvents + $nonDlpErrorEvents) / $totalDLPEvents * 100, 2) } else { 0 }
        
        $warningRate = if ($totalDLPEvents -gt 0) { [math]::Round($eventAnalysis.WarningEvents / $totalDLPEvents * 100, 2) } else { 0 }
        $criticalRate = if ($totalDLPEvents -gt 0) { [math]::Round($dlpCriticalEvents / $totalDLPEvents * 100, 2) } else { 0 }
        
        # Policy sync failure rate (from DLP policy events)
        $totalPolicySyncIssues = ($sourceAnalysisResults.Values | ForEach-Object { $_.PolicySyncIssues } | Measure-Object -Sum).Sum
        $policySyncFailureRate = if ($policySyncAnalysis.TotalPolicyEvents -gt 0) { 
            [math]::Round($policySyncAnalysis.FailedSyncs / $policySyncAnalysis.TotalPolicyEvents * 100, 2) 
        } else { 0 }
        
        # Service restart rate (per day) - only DLP services
        $dlpServiceRestarts = ($sourceAnalysisResults.Values | Where-Object { $_.Source -match "Sense|Defender" } | ForEach-Object { $_.ServiceRestarts } | Measure-Object -Sum).Sum
        $serviceRestartRate = [math]::Round($dlpServiceRestarts / $Days, 2)
        
        # Agent health calculation (inverse of DLP-specific health issues)
        $dlpAgentHealthIssues = $agentHealthAnalysis.CommunicationIssues + $agentHealthAnalysis.HealthIssues
        $agentHealthPercentage = if ($totalDLPEvents -gt 0) { 
            [math]::Round((($totalDLPEvents - $dlpAgentHealthIssues) / $totalDLPEvents) * 100, 2) 
        } else { 100 }
        
        # Display DLP-focused KPI results
        Write-ColorOutput "DLP Event Analysis Summary:" -Color $Colors.Header
        Write-ColorOutput "  Total DLP Events Analysed: $totalDLPEvents" -Color $Colors.Info
        Write-ColorOutput "  DLP-Related Errors: $dlpErrorEvents" -Color $(if ($dlpErrorEvents -gt 0) { $Colors.Warning } else { $Colors.Success })
        Write-ColorOutput "  Non-DLP System Errors: $nonDlpErrorEvents (excluded from DLP KPIs)" -Color $Colors.Info
        Write-ColorOutput "  Sense Service Errors: $($detailedSenseErrors.TotalErrors)" -Color $(if ($detailedSenseErrors.TotalErrors -gt 0) { $Colors.Warning } else { $Colors.Success })
        Write-ColorOutput "  System DLP Service Errors: $($detailedSystemErrors.DLPErrors)" -Color $(if ($detailedSystemErrors.DLPErrors -gt 0) { $Colors.Warning } else { $Colors.Success })
        
        Write-ColorOutput "`nDLP KPI Results:" -Color $Colors.Header
        
        $dlpErrorStatus = if ($dlpErrorRate -lt $EventLogKPIs.ErrorRate) { "[+] Met" } else { "[-] Failed" }
        $dlpErrorColor = if ($dlpErrorRate -lt $EventLogKPIs.ErrorRate) { $Colors.Success } else { $Colors.Error }
        Write-ColorOutput "$dlpErrorStatus DLP Error Rate: $dlpErrorRate% (Target: < $($EventLogKPIs.ErrorRate)%)" -Color $dlpErrorColor
        
        $warningStatus = if ($warningRate -lt $EventLogKPIs.WarningThreshold) { "[+] Met" } else { "[-] Failed" }
        $warningColor = if ($warningRate -lt $EventLogKPIs.WarningThreshold) { $Colors.Success } else { $Colors.Warning }
        Write-ColorOutput "$warningStatus Warning Rate: $warningRate% (Target: < $($EventLogKPIs.WarningThreshold)%)" -Color $warningColor
        
        $criticalStatus = if ($criticalRate -lt $EventLogKPIs.CriticalEventThreshold) { "[+] Met" } else { "[-] Failed" }
        $criticalColor = if ($criticalRate -lt $EventLogKPIs.CriticalEventThreshold) { $Colors.Success } else { $Colors.Error }
        Write-ColorOutput "$criticalStatus Critical Event Rate: $criticalRate% (Target: < $($EventLogKPIs.CriticalEventThreshold)%)" -Color $criticalColor
        
        $policySyncStatus = if ($policySyncFailureRate -lt $EventLogKPIs.PolicySyncFailures) { "[+] Met" } else { "[-] Failed" }
        $policySyncColor = if ($policySyncFailureRate -lt $EventLogKPIs.PolicySyncFailures) { $Colors.Success } else { $Colors.Error }
        Write-ColorOutput "$policySyncStatus Policy Sync Failure Rate: $policySyncFailureRate% (Target: < $($EventLogKPIs.PolicySyncFailures)%)" -Color $policySyncColor
        
        $serviceRestartStatus = if ($serviceRestartRate -lt $EventLogKPIs.ServiceRestartThreshold) { "[+] Met" } else { "[-] Failed" }
        $serviceRestartColor = if ($serviceRestartRate -lt $EventLogKPIs.ServiceRestartThreshold) { $Colors.Success } else { $Colors.Warning }
        Write-ColorOutput "$serviceRestartStatus DLP Service Restart Rate: $serviceRestartRate per day (Target: < $($EventLogKPIs.ServiceRestartThreshold))" -Color $serviceRestartColor
        
        $agentHealthStatus = if ($agentHealthPercentage -gt $EventLogKPIs.AgentHealthThreshold) { "[+] Met" } else { "[-] Failed" }
        $agentHealthColor = if ($agentHealthPercentage -gt $EventLogKPIs.AgentHealthThreshold) { $Colors.Success } else { $Colors.Error }
        Write-ColorOutput "$agentHealthStatus Agent Health: $agentHealthPercentage% (Target: > $($EventLogKPIs.AgentHealthThreshold)%)" -Color $agentHealthColor
        
        # Separate section for non-DLP system health
        if ($nonDlpErrorEvents -gt 0) {
            Write-ColorOutput "`nNon-DLP System Health (Informational):" -Color $Colors.Header
            Write-ColorOutput "  [!] Non-DLP System Errors: $nonDlpErrorEvents" -Color $Colors.Warning
            Write-ColorOutput "  [!] Total System Error Rate (including non-DLP): $totalSystemErrorRate%" -Color $Colors.Warning
            Write-ColorOutput "      Note: These errors are not counted against DLP KPIs" -Color $Colors.Info
            
            # Show top non-DLP error categories
            $topNonDlpErrors = $detailedSystemErrors.NonDLPGroupedErrors | Select-Object -First 3
            if ($topNonDlpErrors.Count -gt 0) {
                Write-ColorOutput "      Top non-DLP issues:" -Color $Colors.Info
                foreach ($errorGroup in $topNonDlpErrors) {
                    $sampleError = $detailedSystemErrors.ErrorDetails | Where-Object { $_.EventID -eq $errorGroup.Name -and -not $_.IsDLPRelevant } | Select-Object -First 1
                    if ($sampleError.ClassificationReason) {
                        Write-ColorOutput "        • Event ID $($errorGroup.Name): $($errorGroup.Count) occurrences ($($sampleError.ClassificationReason))" -Color $Colors.Info
                    }
                }
            }
        }
        
        # Overall health assessment (DLP-focused)
        $dlpKpisPassed = 0
        $totalKPIs = 6
        if ($dlpErrorRate -lt $EventLogKPIs.ErrorRate) { $dlpKpisPassed++ }
        if ($warningRate -lt $EventLogKPIs.WarningThreshold) { $dlpKpisPassed++ }
        if ($criticalRate -lt $EventLogKPIs.CriticalEventThreshold) { $dlpKpisPassed++ }
        if ($policySyncFailureRate -lt $EventLogKPIs.PolicySyncFailures) { $dlpKpisPassed++ }
        if ($serviceRestartRate -lt $EventLogKPIs.ServiceRestartThreshold) { $dlpKpisPassed++ }
        if ($agentHealthPercentage -gt $EventLogKPIs.AgentHealthThreshold) { $dlpKpisPassed++ }
        
        $overallHealthPercentage = [math]::Round($dlpKpisPassed / $totalKPIs * 100, 1)
        $healthStatus = if ($overallHealthPercentage -gt 80) { "Healthy" } elseif ($overallHealthPercentage -gt 60) { "Warning" } else { "Critical" }
        $healthColor = if ($overallHealthPercentage -gt 80) { $Colors.Success } elseif ($overallHealthPercentage -gt 60) { $Colors.Warning } else { $Colors.Error }
        
        Write-ColorOutput "`n[+] Overall DLP Health: $healthStatus ($dlpKpisPassed/$totalKPIs KPIs passed, $overallHealthPercentage%)" -Color $healthColor
        
        # Comprehensive DLP Error Type Analysis
        if ($dlpErrorTypeAnalysis.OverallImpact.TotalDLPErrors -gt 0) {
            Write-ColorOutput "`n" + $('='*60) -Color $Colors.Header
            Write-ColorOutput "COMPREHENSIVE DLP ERROR TYPE ANALYSIS" -Color $Colors.Header
            Write-ColorOutput $('='*60) -Color $Colors.Header
            
            $impact = $dlpErrorTypeAnalysis.OverallImpact
            Write-ColorOutput "`nDLP Error Severity Breakdown:" -Color $Colors.Header
            Write-ColorOutput "  Total DLP Errors: $($impact.TotalDLPErrors)" -Color $Colors.Info
            
            if ($impact.CriticalErrors -gt 0) {
                Write-ColorOutput "  Critical Errors: $($impact.CriticalErrors)" -Color $Colors.Error
            }
            if ($impact.HighSeverityErrors -gt 0) {
                Write-ColorOutput "  High Severity: $($impact.HighSeverityErrors)" -Color $Colors.Error
            }
            if ($impact.MediumSeverityErrors -gt 0) {
                Write-ColorOutput "  Medium Severity: $($impact.MediumSeverityErrors)" -Color $Colors.Warning
            }
            if ($impact.LowSeverityErrors -gt 0) {
                Write-ColorOutput "  Low Severity: $($impact.LowSeverityErrors)" -Color $Colors.Success
            }
            
            Write-ColorOutput "  Primary Risk Level: $($impact.PrimaryRiskLevel)" -Color $(
                switch ($impact.PrimaryRiskLevel) {
                    "Critical" { $Colors.Error }
                    "High" { $Colors.Error }
                    "Medium" { $Colors.Warning }
                    "Low" { $Colors.Success }
                    default { $Colors.Info }
                }
            )
            
            # Detailed Sense Error Analysis
            if ($dlpErrorTypeAnalysis.SenseErrorAnalysis.Count -gt 0) {
                Write-ColorOutput "`nSense Service Error Analysis:" -Color $Colors.Header
                foreach ($eventId in ($dlpErrorTypeAnalysis.SenseErrorAnalysis.Keys | Sort-Object)) {
                    $analysis = $dlpErrorTypeAnalysis.SenseErrorAnalysis[$eventId]
                    $severityColor = switch ($analysis.Severity) {
                        "Critical" { $Colors.Error }
                        "High" { $Colors.Error }
                        "Medium" { $Colors.Warning }
                        "Low" { $Colors.Success }
                        default { $Colors.Info }
                    }
                    
                    Write-ColorOutput "  Event ID $($analysis.EventID) - $($analysis.Description)" -Color $Colors.Info
                    Write-ColorOutput "    Occurrences: $($analysis.Count) ($($analysis.FrequencyPerDay)/day)" -Color $Colors.Info
                    Write-ColorOutput "    Severity: $($analysis.Severity)" -Color $severityColor
                    Write-ColorOutput "    Impact: $($analysis.Impact)" -Color $Colors.Info
                    Write-ColorOutput "    Business Impact: $($analysis.BusinessImpact)" -Color $Colors.Info
                    
                    if ($analysis.Causes.Count -gt 0) {
                        Write-ColorOutput "    Likely Causes:" -Color $Colors.Info
                        foreach ($cause in $analysis.Causes) {
                            Write-ColorOutput "      • $cause" -Color $Colors.Info
                        }
                    }
                    
                    if ($analysis.Actions.Count -gt 0) {
                        Write-ColorOutput "    Recommended Actions:" -Color $Colors.Warning
                        foreach ($action in $analysis.Actions) {
                            Write-ColorOutput "      → $action" -Color $Colors.Info
                        }
                    }
                    Write-ColorOutput ""
                }
            }
            
            # Detailed System DLP Error Analysis
            if ($dlpErrorTypeAnalysis.SystemDLPErrorAnalysis.Count -gt 0) {
                Write-ColorOutput "System DLP Service Error Analysis:" -Color $Colors.Header
                foreach ($eventId in ($dlpErrorTypeAnalysis.SystemDLPErrorAnalysis.Keys | Sort-Object)) {
                    $analysis = $dlpErrorTypeAnalysis.SystemDLPErrorAnalysis[$eventId]
                    $severityColor = switch ($analysis.Severity) {
                        "Critical" { $Colors.Error }
                        "High" { $Colors.Error }
                        "Medium" { $Colors.Warning }
                        "Low" { $Colors.Success }
                        default { $Colors.Info }
                    }
                    
                    Write-ColorOutput "  Event ID $($analysis.EventID) - $($analysis.Description)" -Color $Colors.Info
                    Write-ColorOutput "    Occurrences: $($analysis.Count) ($($analysis.FrequencyPerDay)/day)" -Color $Colors.Info
                    Write-ColorOutput "    Severity: $($analysis.Severity)" -Color $severityColor
                    Write-ColorOutput "    Impact: $($analysis.Impact)" -Color $Colors.Info
                    Write-ColorOutput "    Business Impact: $($analysis.BusinessImpact)" -Color $Colors.Info
                    
                    if ($analysis.Causes.Count -gt 0) {
                        Write-ColorOutput "    Likely Causes:" -Color $Colors.Info
                        foreach ($cause in $analysis.Causes) {
                            Write-ColorOutput "      • $cause" -Color $Colors.Info
                        }
                    }
                    
                    if ($analysis.Actions.Count -gt 0) {
                        Write-ColorOutput "    Recommended Actions:" -Color $Colors.Warning
                        foreach ($action in $analysis.Actions) {
                            Write-ColorOutput "      → $action" -Color $Colors.Info
                        }
                    }
                    Write-ColorOutput ""
                }
            }
            
            # Priority Recommendations
            if ($dlpErrorTypeAnalysis.Recommendations.Count -gt 0) {
                Write-ColorOutput "Priority Action Plan:" -Color $Colors.Header
                
                $priority1Items = $dlpErrorTypeAnalysis.Recommendations | Where-Object { $_.Priority -eq 1 }
                $priority2Items = $dlpErrorTypeAnalysis.Recommendations | Where-Object { $_.Priority -eq 2 }
                
                if ($priority1Items.Count -gt 0) {
                    Write-ColorOutput "`n  Priority 1 (Critical/High Severity):" -Color $Colors.Error
                    foreach ($item in $priority1Items) {
                        Write-ColorOutput "    [!] $($item.Category) - Event ID $($item.EventID)" -Color $Colors.Error
                        Write-ColorOutput "        Issue: $($item.Issue)" -Color $Colors.Info
                        Write-ColorOutput "        Business Impact: $($item.BusinessImpact)" -Color $Colors.Info
                        Write-ColorOutput "        Actions:" -Color $Colors.Warning
                        foreach ($action in $item.Actions) {
                            Write-ColorOutput "          → $action" -Color $Colors.Info
                        }
                        Write-ColorOutput ""
                    }
                }
                
                if ($priority2Items.Count -gt 0) {
                    Write-ColorOutput "  Priority 2 (Medium Severity - High Frequency):" -Color $Colors.Warning
                    foreach ($item in $priority2Items) {
                        Write-ColorOutput "    [!] $($item.Category) - Event ID $($item.EventID)" -Color $Colors.Warning
                        Write-ColorOutput "        Issue: $($item.Issue)" -Color $Colors.Info
                        Write-ColorOutput "        Business Impact: $($item.BusinessImpact)" -Color $Colors.Info
                        Write-ColorOutput "        Actions:" -Color $Colors.Warning
                        foreach ($action in $item.Actions) {
                            Write-ColorOutput "          → $action" -Color $Colors.Info
                        }
                        Write-ColorOutput ""
                    }
                }
                
                if ($priority1Items.Count -eq 0 -and $priority2Items.Count -eq 0) {
                    Write-ColorOutput "  [+] No high-priority DLP issues detected" -Color $Colors.Success
                    Write-ColorOutput "      All detected errors are low severity and do not require immediate action" -Color $Colors.Info
                }
            }
        } else {
            Write-ColorOutput "`n[+] No DLP errors detected - perfect operational status!" -Color $Colors.Success
        }
        
        # Export comprehensive reports with detailed analysis
        if ($ExportReports) {
            Write-ColorOutput "`nExporting comprehensive event log analysis reports..." -Color $Colors.Progress
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            
            # 1. Enhanced KPI Summary with DLP-focused metrics
            $kpiSummary = [PSCustomObject]@{
                Timestamp = Get-Date
                Analysis_Period_Days = $Days
                Total_Events = $eventAnalysis.TotalEvents
                Critical_Events = $eventAnalysis.CriticalEvents
                Error_Events = $eventAnalysis.ErrorEvents
                Warning_Events = $eventAnalysis.WarningEvents
                Info_Events = $eventAnalysis.InfoEvents
                # DLP-specific metrics
                DLP_Error_Events = $dlpErrorEvents
                DLP_Error_Rate_Percentage = $dlpErrorRate
                DLP_Error_Rate_Status = if ($dlpErrorRate -lt $EventLogKPIs.ErrorRate) { "Met" } else { "Failed" }
                Non_DLP_Error_Events = $nonDlpErrorEvents
                Total_System_Error_Rate = $totalSystemErrorRate
                # Original KPIs
                Warning_Rate_Percentage = $warningRate
                Warning_Rate_Status = if ($warningRate -lt $EventLogKPIs.WarningThreshold) { "Met" } else { "Failed" }
                Critical_Rate_Percentage = $criticalRate
                Critical_Rate_Status = if ($criticalRate -lt $EventLogKPIs.CriticalEventThreshold) { "Met" } else { "Failed" }
                Policy_Sync_Failure_Rate = $policySyncFailureRate
                Policy_Sync_Status = if ($policySyncFailureRate -lt $EventLogKPIs.PolicySyncFailures) { "Met" } else { "Failed" }
                Service_Restart_Rate_Per_Day = $serviceRestartRate
                Service_Restart_Status = if ($serviceRestartRate -lt $EventLogKPIs.ServiceRestartThreshold) { "Met" } else { "Failed" }
                Agent_Health_Percentage = $agentHealthPercentage
                Agent_Health_Status = if ($agentHealthPercentage -gt $EventLogKPIs.AgentHealthThreshold) { "Met" } else { "Failed" }
                Overall_DLP_Health_Status = $healthStatus
                Overall_Health_Percentage = $overallHealthPercentage
                DLP_KPIs_Passed = $dlpKpisPassed
                Total_KPIs = $totalKPIs
                # Detailed analysis metrics
                System_Errors_Total = $detailedSystemErrors.TotalErrors
                System_DLP_Errors = $detailedSystemErrors.DLPErrors
                System_Non_DLP_Errors = $detailedSystemErrors.NonDLPErrors
                Sense_Errors_Found = $detailedSenseErrors.TotalErrors
                Agent_Health_Events = $agentHealthAnalysis.TotalHealthEvents
                Service_Events = $agentHealthAnalysis.ServiceEvents
                Communication_Issues = $agentHealthAnalysis.CommunicationIssues
                Policy_Sync_Events = $policySyncAnalysis.TotalPolicyEvents
                Policy_Sync_Failures = $policySyncAnalysis.FailedSyncs
                Policy_Sync_Success_Rate = $policySyncAnalysis.SyncSuccessRate
                # DLP Error Type Analysis Results
                Total_DLP_Errors_Analyzed = $dlpErrorTypeAnalysis.OverallImpact.TotalDLPErrors
                Critical_Severity_Errors = $dlpErrorTypeAnalysis.OverallImpact.CriticalErrors
                High_Severity_Errors = $dlpErrorTypeAnalysis.OverallImpact.HighSeverityErrors
                Medium_Severity_Errors = $dlpErrorTypeAnalysis.OverallImpact.MediumSeverityErrors
                Low_Severity_Errors = $dlpErrorTypeAnalysis.OverallImpact.LowSeverityErrors
                Primary_Risk_Level = $dlpErrorTypeAnalysis.OverallImpact.PrimaryRiskLevel
                Priority_1_Recommendations = $dlpErrorTypeAnalysis.Recommendations | Where-Object { $_.Priority -eq 1 } | Measure-Object | Select-Object -ExpandProperty Count
                Priority_2_Recommendations = $dlpErrorTypeAnalysis.Recommendations | Where-Object { $_.Priority -eq 2 } | Measure-Object | Select-Object -ExpandProperty Count
            }
            
            $kpiCsvPath = "DLP_EventLog_KPI_Summary_Enhanced_$timestamp.csv"
            $kpiSummary | Export-Csv -Path $kpiCsvPath -NoTypeInformation -Encoding UTF8
            Write-ColorOutput "  [+] Enhanced KPI summary: $kpiCsvPath" -Color $Colors.Success
            
            # 2. DLP-Related System Errors Export (separate from non-DLP)
            if ($detailedSystemErrors.ErrorDetails.Count -gt 0) {
                $dlpSystemErrors = $detailedSystemErrors.ErrorDetails | Where-Object { $_.IsDLPRelevant }
                $nonDlpSystemErrors = $detailedSystemErrors.ErrorDetails | Where-Object { -not $_.IsDLPRelevant }
                
                if ($dlpSystemErrors.Count -gt 0) {
                    $dlpSystemErrorsCsvPath = "DLP_EventLog_DLP_System_Errors_$timestamp.csv"
                    $dlpSystemErrors | Export-Csv -Path $dlpSystemErrorsCsvPath -NoTypeInformation -Encoding UTF8
                    Write-ColorOutput "  [+] DLP-related System errors: $dlpSystemErrorsCsvPath" -Color $Colors.Success
                }
                
                if ($nonDlpSystemErrors.Count -gt 0) {
                    $nonDlpSystemErrorsCsvPath = "DLP_EventLog_Non_DLP_System_Errors_$timestamp.csv"
                    $nonDlpSystemErrors | Export-Csv -Path $nonDlpSystemErrorsCsvPath -NoTypeInformation -Encoding UTF8
                    Write-ColorOutput "  [+] Non-DLP System errors (informational): $nonDlpSystemErrorsCsvPath" -Color $Colors.Info
                }
                
                # Combined System errors with classification
                $systemErrorsCsvPath = "DLP_EventLog_System_Errors_Classified_$timestamp.csv"
                $detailedSystemErrors.ErrorDetails | Export-Csv -Path $systemErrorsCsvPath -NoTypeInformation -Encoding UTF8
                Write-ColorOutput "  [+] All System errors (classified): $systemErrorsCsvPath" -Color $Colors.Success
            }
            
            # 3. Detailed Sense Errors Export
            if ($detailedSenseErrors.ErrorDetails.Count -gt 0) {
                $senseErrorsCsvPath = "DLP_EventLog_Sense_Errors_$timestamp.csv"
                $detailedSenseErrors.ErrorDetails | Export-Csv -Path $senseErrorsCsvPath -NoTypeInformation -Encoding UTF8
                Write-ColorOutput "  [+] Sense errors details: $senseErrorsCsvPath" -Color $Colors.Success
            }
            
            # 4. Agent Health Details Export
            if ($agentHealthAnalysis.HealthDetails.Count -gt 0) {
                $agentHealthCsvPath = "DLP_EventLog_Agent_Health_$timestamp.csv"
                $agentHealthAnalysis.HealthDetails | Export-Csv -Path $agentHealthCsvPath -NoTypeInformation -Encoding UTF8
                Write-ColorOutput "  [+] Agent health details: $agentHealthCsvPath" -Color $Colors.Success
            }
            
            # 5. Policy Sync Analysis Export
            if ($policySyncAnalysis.PolicyDetails.Count -gt 0) {
                $policySyncCsvPath = "DLP_EventLog_Policy_Sync_$timestamp.csv"
                $policySyncAnalysis.PolicyDetails | Export-Csv -Path $policySyncCsvPath -NoTypeInformation -Encoding UTF8
                Write-ColorOutput "  [+] Policy sync details: $policySyncCsvPath" -Color $Colors.Success
            }
            
            # 6. Error Summary by Event ID with DLP Classification
            $errorSummaryByID = @()
            
            # DLP System error ID summary
            foreach ($group in $detailedSystemErrors.DLPGroupedErrors) {
                $sampleError = $detailedSystemErrors.ErrorDetails | Where-Object { $_.EventID -eq $group.Name -and $_.IsDLPRelevant } | Select-Object -First 1
                $errorSummaryByID += [PSCustomObject]@{
                    Source = "System"
                    Category = "DLP-Related"
                    EventID = $group.Name
                    Count = $group.Count
                    Percentage = [math]::Round(($group.Count / $detailedSystemErrors.DLPErrors) * 100, 2)
                    SampleMessage = if ($sampleError) { $sampleError.Message.Substring(0, [Math]::Min(200, $sampleError.Message.Length)) } else { "N/A" }
                    ClassificationReason = if ($sampleError) { $sampleError.ClassificationReason } else { "N/A" }
                    FirstOccurrence = ($group.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
                    LastOccurrence = ($group.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
                }
            }
            
            # Non-DLP System error ID summary
            foreach ($group in $detailedSystemErrors.NonDLPGroupedErrors) {
                $sampleError = $detailedSystemErrors.ErrorDetails | Where-Object { $_.EventID -eq $group.Name -and -not $_.IsDLPRelevant } | Select-Object -First 1
                $errorSummaryByID += [PSCustomObject]@{
                    Source = "System"
                    Category = "Non-DLP-System"
                    EventID = $group.Name
                    Count = $group.Count
                    Percentage = [math]::Round(($group.Count / $detailedSystemErrors.NonDLPErrors) * 100, 2)
                    SampleMessage = if ($sampleError) { $sampleError.Message.Substring(0, [Math]::Min(200, $sampleError.Message.Length)) } else { "N/A" }
                    ClassificationReason = if ($sampleError) { $sampleError.ClassificationReason } else { "N/A" }
                    FirstOccurrence = ($group.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
                    LastOccurrence = ($group.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
                }
            }
            
            # Sense error ID summary (always DLP-related)
            foreach ($group in $detailedSenseErrors.GroupedErrors) {
                $errorSummaryByID += [PSCustomObject]@{
                    Source = "Sense"
                    Category = "DLP-Core"
                    EventID = $group.Name
                    Count = $group.Count
                    Percentage = [math]::Round(($group.Count / $detailedSenseErrors.TotalErrors) * 100, 2)
                    SampleMessage = ($group.Group | Select-Object -First 1).Message.Substring(0, [Math]::Min(200, ($group.Group | Select-Object -First 1).Message.Length))
                    ClassificationReason = "Microsoft Defender for Endpoint core error"
                    FirstOccurrence = ($group.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
                    LastOccurrence = ($group.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
                }
            }
            
            if ($errorSummaryByID.Count -gt 0) {
                $errorSummaryCsvPath = "DLP_EventLog_Error_Summary_By_ID_Classified_$timestamp.csv"
                $errorSummaryByID | Sort-Object Category, Count -Descending | Export-Csv -Path $errorSummaryCsvPath -NoTypeInformation -Encoding UTF8
                Write-ColorOutput "  [+] Error summary by Event ID (classified): $errorSummaryCsvPath" -Color $Colors.Success
            }
            
            # 7. Daily Event Trend Export
            $dailyTrend = @()
            foreach ($date in ($eventAnalysis.EventsByDay.Keys | Sort-Object)) {
                $dailyTrend += [PSCustomObject]@{
                    Date = $date
                    Total_Events = $eventAnalysis.EventsByDay[$date]
                    # Add breakdown if available
                    System_Events = ($detailedSystemErrors.ErrorDetails | Where-Object { $_.TimeCreated.Date.ToString('yyyy-MM-dd') -eq $date }).Count
                    Sense_Events = ($detailedSenseErrors.ErrorDetails | Where-Object { $_.TimeCreated.Date.ToString('yyyy-MM-dd') -eq $date }).Count
                    Agent_Health_Events = ($agentHealthAnalysis.HealthDetails | Where-Object { $_.TimeCreated.Date.ToString('yyyy-MM-dd') -eq $date }).Count
                }
            }
            
            if ($dailyTrend.Count -gt 0) {
                $dailyTrendCsvPath = "DLP_EventLog_Daily_Trend_$timestamp.csv"
                $dailyTrend | Export-Csv -Path $dailyTrendCsvPath -NoTypeInformation -Encoding UTF8
                Write-ColorOutput "  [+] Daily trend analysis: $dailyTrendCsvPath" -Color $Colors.Success
            }
            
            # 8. Comprehensive source analysis with detailed metrics
            $sourceDetails = @()
            foreach ($sourceName in $sourceAnalysisResults.Keys) {
                $analysis = $sourceAnalysisResults[$sourceName]
                $sourceDetails += [PSCustomObject]@{
                    Source = $sourceName
                    Description = $analysis.Description
                    Total_Events = $analysis.TotalEvents
                    Critical_Events = $analysis.CriticalEvents
                    Error_Events = $analysis.ErrorEvents
                    Warning_Events = $analysis.WarningEvents
                    Info_Events = $analysis.InfoEvents
                    Service_Restarts = $analysis.ServiceRestarts
                    Policy_Sync_Issues = $analysis.PolicySyncIssues
                    Agent_Health_Issues = $analysis.AgentHealthIssues
                    # Additional metrics based on detailed analysis
                    Detailed_System_Errors = if ($sourceName -eq "System") { $detailedSystemErrors.TotalErrors } else { 0 }
                    Detailed_Sense_Errors = if ($sourceName -eq "Microsoft-Windows-Sense") { $detailedSenseErrors.TotalErrors } else { 0 }
                    Health_Communication_Issues = if ($sourceName -eq "System") { $agentHealthAnalysis.CommunicationIssues } else { 0 }
                    Policy_Sync_Success_Rate = $policySyncAnalysis.SyncSuccessRate
                }
            }
            
            $sourceCsvPath = "DLP_EventLog_Source_Analysis_Enhanced_$timestamp.csv"
            $sourceDetails | Export-Csv -Path $sourceCsvPath -NoTypeInformation -Encoding UTF8
            
            # 9. Comprehensive DLP Error Type Analysis Export
            if ($dlpErrorTypeAnalysis.OverallImpact.TotalDLPErrors -gt 0) {
                $dlpErrorAnalysisDetails = @()
                
                # Export Sense error analysis
                foreach ($eventId in $dlpErrorTypeAnalysis.SenseErrorAnalysis.Keys) {
                    $analysis = $dlpErrorTypeAnalysis.SenseErrorAnalysis[$eventId]
                    $dlpErrorAnalysisDetails += [PSCustomObject]@{
                        Error_Source = "Sense"
                        Event_ID = $analysis.EventID
                        Description = $analysis.Description
                        Count = $analysis.Count
                        Frequency_Per_Day = $analysis.FrequencyPerDay
                        Severity = $analysis.Severity
                        Impact = $analysis.Impact
                        Business_Impact = $analysis.BusinessImpact
                        Likely_Causes = $analysis.Causes -join "; "
                        Recommended_Actions = $analysis.Actions -join "; "
                        Category = "Microsoft Defender for Endpoint Core"
                    }
                }
                
                # Export System DLP error analysis
                foreach ($eventId in $dlpErrorTypeAnalysis.SystemDLPErrorAnalysis.Keys) {
                    $analysis = $dlpErrorTypeAnalysis.SystemDLPErrorAnalysis[$eventId]
                    $dlpErrorAnalysisDetails += [PSCustomObject]@{
                        Error_Source = "System"
                        Event_ID = $analysis.EventID
                        Description = $analysis.Description
                        Count = $analysis.Count
                        Frequency_Per_Day = $analysis.FrequencyPerDay
                        Severity = $analysis.Severity
                        Impact = $analysis.Impact
                        Business_Impact = $analysis.BusinessImpact
                        Likely_Causes = $analysis.Causes -join "; "
                        Recommended_Actions = $analysis.Actions -join "; "
                        Category = "System DLP Services"
                    }
                }
                
                if ($dlpErrorAnalysisDetails.Count -gt 0) {
                    $dlpErrorAnalysisCsvPath = "DLP_EventLog_Error_Type_Analysis_$timestamp.csv"
                    $dlpErrorAnalysisDetails | Sort-Object Severity, Frequency_Per_Day -Descending | Export-Csv -Path $dlpErrorAnalysisCsvPath -NoTypeInformation -Encoding UTF8
                    Write-ColorOutput "  [+] DLP error type analysis: $dlpErrorAnalysisCsvPath" -Color $Colors.Success
                }
                
                # Export priority recommendations
                if ($dlpErrorTypeAnalysis.Recommendations.Count -gt 0) {
                    $recommendationsDetails = @()
                    foreach ($recommendation in $dlpErrorTypeAnalysis.Recommendations) {
                        $recommendationsDetails += [PSCustomObject]@{
                            Priority = $recommendation.Priority
                            Category = $recommendation.Category
                            Event_ID = $recommendation.EventID
                            Issue = $recommendation.Issue
                            Business_Impact = $recommendation.BusinessImpact
                            Actions = $recommendation.Actions -join "; "
                            Priority_Description = if ($recommendation.Priority -eq 1) { "Critical/High Severity" } else { "Medium Severity - High Frequency" }
                        }
                    }
                    
                    $recommendationsCsvPath = "DLP_EventLog_Priority_Recommendations_$timestamp.csv"
                    $recommendationsDetails | Sort-Object Priority, Event_ID | Export-Csv -Path $recommendationsCsvPath -NoTypeInformation -Encoding UTF8
                    Write-ColorOutput "  [+] Priority recommendations: $recommendationsCsvPath" -Color $Colors.Success
                }
            }
        }
        
        # Enhanced recommendations based on DLP-focused analysis
        Write-ColorOutput "`nDLP-Focused Recommendations Based on Analysis:" -Color $Colors.Header
        
        if ($dlpErrorRate -ge $EventLogKPIs.ErrorRate) {
            Write-ColorOutput "  [!] CRITICAL: DLP error rate ($dlpErrorRate%) exceeds threshold" -Color $Colors.Error
            Write-ColorOutput "      DLP-specific root cause analysis:" -Color $Colors.Info
            
            if ($detailedSenseErrors.TotalErrors -gt 0) {
                Write-ColorOutput "        • Sense service errors: $($detailedSenseErrors.TotalErrors) found" -Color $Colors.Info
                if ($detailedSenseErrors.GroupedErrors.Count -gt 0) {
                    $topSenseError = $detailedSenseErrors.GroupedErrors | Sort-Object Count -Descending | Select-Object -First 1
                    Write-ColorOutput "        • Top Sense error ID: $($topSenseError.Name) ($($topSenseError.Count) occurrences)" -Color $Colors.Info
                    
                    # Specific guidance for common Sense errors
                    switch ($topSenseError.Name) {
                        "101" { 
                            Write-ColorOutput "          → Network Detection & Response startup failures" -Color $Colors.Warning
                            Write-ColorOutput "          → Check system resources and service dependencies" -Color $Colors.Info
                        }
                        "405" { 
                            Write-ColorOutput "          → Authentication service communication failures" -Color $Colors.Warning
                            Write-ColorOutput "          → Verify internet connectivity and DNS resolution" -Color $Colors.Info
                        }
                    }
                }
            }
            
            if ($detailedSystemErrors.DLPErrors -gt 0) {
                Write-ColorOutput "        • DLP System service errors: $($detailedSystemErrors.DLPErrors) found" -Color $Colors.Info
                if ($detailedSystemErrors.DLPGroupedErrors.Count -gt 0) {
                    $topDlpSystemError = $detailedSystemErrors.DLPGroupedErrors | Sort-Object Count -Descending | Select-Object -First 1
                    Write-ColorOutput "        • Top DLP System error ID: $($topDlpSystemError.Name) ($($topDlpSystemError.Count) occurrences)" -Color $Colors.Info
                }
            }
            
            Write-ColorOutput "      Priority DLP actions:" -Color $Colors.Warning
            Write-ColorOutput "        1. Focus on Sense service stability (Microsoft Defender for Endpoint)" -Color $Colors.Info
            Write-ColorOutput "        2. Check network connectivity to *.securitycenter.windows.com" -Color $Colors.Info
            Write-ColorOutput "        3. Verify DNS resolution for Microsoft ATP services" -Color $Colors.Info
            Write-ColorOutput "        4. Review system resources during DLP agent startup" -Color $Colors.Info
            if ($ExportReports) {
                Write-ColorOutput "        5. Review DLP-specific error CSV files for detailed patterns" -Color $Colors.Info
            }
        } else {
            Write-ColorOutput "  [+] DLP error rate ($dlpErrorRate%) is within acceptable limits" -Color $Colors.Success
            Write-ColorOutput "      Your DLP services are operating within Microsoft's recommended thresholds" -Color $Colors.Success
        }
        
        # Non-DLP system issues (informational guidance)
        if ($nonDlpErrorEvents -gt 0) {
            Write-ColorOutput "`n  [i] Non-DLP System Issues (Informational):" -Color $Colors.Info
            Write-ColorOutput "      • $nonDlpErrorEvents non-DLP system errors detected" -Color $Colors.Info
            Write-ColorOutput "      • These do not impact your DLP KPIs or Microsoft Defender functionality" -Color $Colors.Info
            
            $topNonDlpError = $detailedSystemErrors.NonDLPGroupedErrors | Sort-Object Count -Descending | Select-Object -First 1
            if ($topNonDlpError) {
                $sampleNonDlp = $detailedSystemErrors.ErrorDetails | Where-Object { $_.EventID -eq $topNonDlpError.Name -and -not $_.IsDLPRelevant } | Select-Object -First 1
                Write-ColorOutput "      • Primary issue: Event ID $($topNonDlpError.Name) ($($topNonDlpError.Count) occurrences)" -Color $Colors.Info
                Write-ColorOutput "        → $($sampleNonDlp.ClassificationReason)" -Color $Colors.Info
                
                # Specific guidance for common non-DLP errors
                switch ($topNonDlpError.Name) {
                    "7000" {
                        if ($sampleNonDlp.Message -match "IntelTACD") {
                            Write-ColorOutput "        → Consider updating Intel drivers or disabling unused Intel services" -Color $Colors.Info
                        }
                    }
                    "7009" {
                        Write-ColorOutput "        → Service startup timeout - review system boot performance" -Color $Colors.Info
                    }
                    "7031" {
                        Write-ColorOutput "        → Service crash - check Windows Update status" -Color $Colors.Info
                    }
                }
            }
            
            Write-ColorOutput "      • These issues can be addressed during routine maintenance windows" -Color $Colors.Info
        }
        
        if ($agentHealthPercentage -le $EventLogKPIs.AgentHealthThreshold) {
            Write-ColorOutput "`n  [!] CRITICAL: DLP Agent health below threshold ($agentHealthPercentage%)" -Color $Colors.Error
            Write-ColorOutput "      Agent health breakdown:" -Color $Colors.Info
            Write-ColorOutput "        • Service events: $($agentHealthAnalysis.ServiceEvents)" -Color $Colors.Info
            Write-ColorOutput "        • Communication issues: $($agentHealthAnalysis.CommunicationIssues)" -Color $Colors.Info
            Write-ColorOutput "        • Health-specific issues: $($agentHealthAnalysis.HealthIssues)" -Color $Colors.Info
            Write-ColorOutput "      Actions:" -Color $Colors.Warning
            Write-ColorOutput "        1. Check network connectivity to Microsoft Defender cloud services" -Color $Colors.Info
            Write-ColorOutput "        2. Verify system time synchronisation with time.windows.com" -Color $Colors.Info
            Write-ColorOutput "        3. Review proxy/firewall configurations for *.securitycenter.windows.com" -Color $Colors.Info
            Write-ColorOutput "        4. Monitor system resource utilisation during DLP operations" -Color $Colors.Info
        } else {
            Write-ColorOutput "`n  [+] DLP Agent health is excellent ($agentHealthPercentage%)" -Color $Colors.Success
        }
        
        if ($policySyncAnalysis.TotalPolicyEvents -gt 0) {
            $syncSuccessRate = $policySyncAnalysis.SyncSuccessRate
            Write-ColorOutput "`n  [+] DLP Policy synchronisation analysis:" -Color $Colors.Info
            Write-ColorOutput "      • Total policy events: $($policySyncAnalysis.TotalPolicyEvents)" -Color $Colors.Info
            Write-ColorOutput "      • Success rate: $syncSuccessRate%" -Color $(if ($syncSuccessRate -gt 90) { $Colors.Success } else { $Colors.Warning })
            Write-ColorOutput "      • Failed syncs: $($policySyncAnalysis.FailedSyncs)" -Color $(if ($policySyncAnalysis.FailedSyncs -eq 0) { $Colors.Success } else { $Colors.Warning })
            
            if ($syncSuccessRate -eq 100) {
                Write-ColorOutput "      • Perfect policy sync rate - DLP policies are updating correctly" -Color $Colors.Success
            } elseif ($policySyncAnalysis.FailedSyncs -gt 0) {
                Write-ColorOutput "      Actions for sync failures:" -Color $Colors.Warning
                Write-ColorOutput "        1. Check Microsoft 365 Defender portal service health" -Color $Colors.Info
                Write-ColorOutput "        2. Verify internet connectivity to Microsoft cloud services" -Color $Colors.Info
                Write-ColorOutput "        3. Review Microsoft Defender for Endpoint onboarding status" -Color $Colors.Info
            }
        } else {
            Write-ColorOutput "`n  [+] No DLP policy synchronisation issues detected" -Color $Colors.Success
        }
        
        if ($warningRate -ge $EventLogKPIs.WarningThreshold) {
            Write-ColorOutput "`n  [!] WARNING: Warning rate ($warningRate%) exceeds threshold" -Color $Colors.Warning
            Write-ColorOutput "      Action: Investigate warning events for policy tuning opportunities" -Color $Colors.Info
        } else {
            Write-ColorOutput "`n  [+] Warning rate is acceptable ($warningRate%)" -Color $Colors.Success
        }
        
        if ($serviceRestartRate -ge $EventLogKPIs.ServiceRestartThreshold) {
            Write-ColorOutput "`n  [!] WARNING: Frequent DLP service restarts ($serviceRestartRate per day)" -Color $Colors.Warning
            Write-ColorOutput "      Action: Investigate DLP service stability and resource constraints" -Color $Colors.Info
        } else {
            Write-ColorOutput "`n  [+] DLP service restart rate is normal ($serviceRestartRate per day)" -Color $Colors.Success
        }
        
        # Overall health guidance
        if ($overallHealthPercentage -gt 80) {
            Write-ColorOutput "`n  [+] Overall DLP health is excellent ($overallHealthPercentage%)" -Color $Colors.Success
            Write-ColorOutput "      • Your DLP deployment meets Microsoft's recommended standards" -Color $Colors.Info
            Write-ColorOutput "      • Continue current monitoring schedule" -Color $Colors.Info
            Write-ColorOutput "      • Focus on maintaining current performance levels" -Color $Colors.Info
            if ($ExportReports) {
                Write-ColorOutput "      • Use exported trend data for capacity planning" -Color $Colors.Info
            }
        } else {
            Write-ColorOutput "`n  [!] DLP health needs attention ($overallHealthPercentage%)" -Color $Colors.Warning
            Write-ColorOutput "      • Increase monitoring frequency to daily" -Color $Colors.Info
            Write-ColorOutput "      • Address high-priority DLP issues first (Sense errors and agent health)" -Color $Colors.Info
            Write-ColorOutput "      • Consider engaging Microsoft Support for persistent DLP issues" -Color $Colors.Info
        }
        
        # Export-specific recommendations
        if ($ExportReports) {
            Write-ColorOutput "`nData Analysis Recommendations:" -Color $Colors.Header
            Write-ColorOutput "  [+] CSV files exported with DLP classification" -Color $Colors.Success
            Write-ColorOutput "      • DLP_System_Errors.csv: Focus on these for DLP troubleshooting" -Color $Colors.Info
            Write-ColorOutput "      • Non_DLP_System_Errors.csv: Address during maintenance windows" -Color $Colors.Info
            Write-ColorOutput "      • Error_Summary_By_ID_Classified.csv: Prioritise by category and count" -Color $Colors.Info
            Write-ColorOutput "      • Daily_Trend.csv: Monitor DLP event patterns for capacity planning" -Color $Colors.Info
            Write-ColorOutput "      • Compare KPI_Summary across multiple runs to track DLP improvements" -Color $Colors.Info
        } else {
            Write-ColorOutput "`nNext Steps:" -Color $Colors.Header
            Write-ColorOutput "  • Re-run with -ExportReports switch for detailed DLP vs non-DLP analysis" -Color $Colors.Info
            Write-ColorOutput "  • Schedule regular DLP monitoring (weekly for healthy systems)" -Color $Colors.Info
        }
        
    } else {
        Write-ColorOutput "`nNo DLP-related events found in the last $Days days" -Color $Colors.Warning
        Write-ColorOutput "This could indicate:" -Color $Colors.Info
        Write-ColorOutput "  - DLP services are not generating events (check if DLP is active)" -Color $Colors.Info
        Write-ColorOutput "  - Event logs have been cleared recently" -Color $Colors.Info
        Write-ColorOutput "  - Event log sources are not configured properly" -Color $Colors.Info
        Write-ColorOutput "  - DLP is operating normally without issues (ideal scenario)" -Color $Colors.Info
    }
    
    Write-ColorOutput "`n[+] DLP Event Log analysis completed" -Color $Colors.Success

} catch {
    Write-ColorOutput "`nERROR: $($_.Exception.Message)" -Color $Colors.Error
    Write-ColorOutput "Line: $($_.InvocationInfo.ScriptLineNumber)" -Color $Colors.Info
    exit 1
}

Write-ColorOutput "`n" + $('='*80) -Color $Colors.Header
Write-ColorOutput "END OF DLP EVENT LOG MONITOR" -Color $Colors.Header
Write-ColorOutput $('='*80) -Color $Colors.Header