<# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
# Copyright (c) 2025 Global Micro Solutions (Pty) Ltd
# All rights reserved

.SYNOPSIS
    Master DLP Monitoring Suite - Interactive orchestration of DLP monitoring scripts with menu-driven selection.

.DESCRIPTION
    Comprehensive orchestration script that executes DLP monitoring components with an interactive menu system.
    Provides unified reporting and KPI tracking across policy activity, endpoint performance, file latency,
    network impact, user experience, and event log analysis. Features intelligent menu-driven selection
    for different monitoring scenarios.

.PARAMETER MonitoringMode
    Mode of operation: 'Full' (all scripts), 'Essential' (core scripts only), 'Performance' (system impact only), 'Policy' (policy and events only), or 'Custom' (individual selection).
    If not specified, an interactive menu will be displayed.

.PARAMETER Duration
    Duration in minutes for performance monitoring components (default: 10).

.PARAMETER ExportReports
    Export consolidated CSV reports and individual script outputs.

.PARAMETER QuickTest
    Run all scripts in quick test mode for rapid assessment.

.PARAMETER ScriptDirectory
    Directory containing the DLP monitoring scripts (default: current directory).

.PARAMETER UserPrincipalName
    UPN for policy activity monitoring (required for policy analysis).

.PARAMETER IncludeUserSurvey
    Include user experience survey collection in the monitoring cycle.

.PARAMETER Interactive
    Force interactive confirmation prompts even when parameters are provided.

.PARAMETER SkipMenu
    Skip the interactive menu and use default Essential mode if no MonitoringMode specified.

.EXAMPLE
    .\Master-DLPMonitoring.ps1
    Shows interactive menu to select monitoring configuration

.EXAMPLE
    .\Master-DLPMonitoring.ps1 -MonitoringMode Essential -ExportReports
    Runs essential monitoring components with CSV export

.EXAMPLE
    .\Master-DLPMonitoring.ps1 -MonitoringMode Full -UserPrincipalName admin@domain.com -Duration 15
    Complete monitoring suite with extended performance monitoring

.EXAMPLE
    .\Master-DLPMonitoring.ps1 -QuickTest -ExportReports
    Shows menu for quick test mode selection with reporting

.WARRANTY
    Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
    either express or implied. See the Apache-2.0 WITH Commons-Clause License for the specific language
    governing permissions and limitations under the License.
#>

[CmdletBinding()]
param(
    [string]$MonitoringMode = "",
    [int]$Duration = 10,
    [switch]$ExportReports,
    [switch]$QuickTest,
    [string]$ScriptDirectory = ".",
    [string]$UserPrincipalName,
    [switch]$IncludeUserSurvey,
    [switch]$Interactive,
    [switch]$SkipMenu
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

function Show-MonitoringMenu {
    param([hashtable]$MonitoringComponents)
    
    Write-ColorOutput "`n$('='*80)" -Color $Colors.Header
    Write-ColorOutput "   MICROSOFT PURVIEW DLP MONITORING SUITE" -Color $Colors.Header
    Write-ColorOutput "            Select Monitoring Configuration" -Color $Colors.Info
    Write-ColorOutput $('='*80) -Color $Colors.Header
    
    # Define monitoring profiles with descriptions
    $monitoringProfiles = @(
        @{
            Index = 1
            Name = "Full"
            DisplayName = "Full Monitoring Suite"
            Description = "Complete DLP health assessment across all components"
            Components = @("PolicyActivity", "EndpointPerformance", "FileLatency", "NetworkImpact", "UserExperience", "EventLogs")
            EstimatedDuration = "15-25 minutes"
            Recommendation = "Recommended for monthly comprehensive assessments"
        },
        @{
            Index = 2
            Name = "Essential"
            DisplayName = "Essential Monitoring"
            Description = "Core DLP health monitoring for routine checks"
            Components = @("PolicyActivity", "EndpointPerformance", "FileLatency", "EventLogs")
            EstimatedDuration = "8-12 minutes"
            Recommendation = "Recommended for weekly health checks"
        },
        @{
            Index = 3
            Name = "Performance"
            DisplayName = "Performance Impact Analysis"
            Description = "Focus on system performance and user experience impact"
            Components = @("EndpointPerformance", "FileLatency", "NetworkImpact")
            EstimatedDuration = "10-15 minutes"
            Recommendation = "Use when investigating performance concerns"
        },
        @{
            Index = 4
            Name = "Policy"
            DisplayName = "Policy & Health Analysis"
            Description = "DLP policy effectiveness and operational health"
            Components = @("PolicyActivity", "EventLogs")
            EstimatedDuration = "5-8 minutes"
            Recommendation = "Quick policy compliance and health assessment"
        }
    )
    
    # Display profile options
    foreach ($monitoringProfile in $monitoringProfiles) {
        $componentCount = $monitoringProfile.Components.Count
        $componentList = $monitoringProfile.Components | ForEach-Object {
            $MonitoringComponents[$_].Description
        }
        
        Write-ColorOutput "`n  [$($monitoringProfile.Index)] $($monitoringProfile.DisplayName)" -Color $Colors.Success
        Write-ColorOutput "      $($monitoringProfile.Description)" -Color $Colors.Info
        Write-ColorOutput "      Components: $componentCount ($($componentList -join ', '))" -Color $Colors.Progress
        Write-ColorOutput "      Duration: $($monitoringProfile.EstimatedDuration)" -Color $Colors.Progress
        Write-ColorOutput "      $($monitoringProfile.Recommendation)" -Color $Colors.Info
    }
    
    # Add individual component selection
    Write-ColorOutput "`n  [5] Individual Component Selection" -Color $Colors.Warning
    Write-ColorOutput "      Choose specific monitoring components to run" -Color $Colors.Info
    Write-ColorOutput "      Duration: Variable based on selection" -Color $Colors.Progress
    Write-ColorOutput "      Advanced users - customize your monitoring scope" -Color $Colors.Info
    
    # Add exit option
    Write-ColorOutput "`n  [6] Exit" -Color $Colors.Error
    Write-ColorOutput "      Cancel monitoring and exit" -Color $Colors.Info
    
    Write-ColorOutput "`n$('='*80)" -Color $Colors.Header
    Write-ColorOutput "Configuration Options:" -Color $Colors.Info
    Write-ColorOutput "  Duration: $Duration minutes (for performance monitoring)" -Color $Colors.Success
    Write-ColorOutput "  Export Reports: $(if ($ExportReports) { 'Enabled' } else { 'Disabled' })" -Color $Colors.Success
    Write-ColorOutput "  Quick Test: $(if ($QuickTest) { 'Enabled' } else { 'Disabled' })" -Color $Colors.Success
    if ($UserPrincipalName) {
        Write-ColorOutput "  User Principal: $UserPrincipalName" -Color $Colors.Success
    }
    Write-ColorOutput "`nTip: You can also run with parameters to skip this menu:" -Color $Colors.Info
    Write-ColorOutput "  .\Master-DLPMonitoring.ps1 -MonitoringMode Essential -ExportReports" -Color $Colors.Success
    Write-ColorOutput "  .\Master-DLPMonitoring.ps1 -MonitoringMode Performance -Duration 15" -Color $Colors.Success
    Write-ColorOutput $('-'*80) -Color $Colors.Header
    
    do {
        Write-ColorOutput "`nSelect monitoring configuration [1-6]: " -Color $Colors.Warning -NoNewline
        $selection = Read-Host
        
        if ($selection -match '^\d+$') {
            $selectionNum = [int]$selection
            
            if ($selectionNum -ge 1 -and $selectionNum -le 4) {
                $selectedProfile = $profiles[$selectionNum - 1]
                Write-ColorOutput "`n[+] Selected: $($selectedProfile.DisplayName)" -Color $Colors.Success
                Write-ColorOutput "  Duration: $($selectedProfile.EstimatedDuration)" -Color $Colors.Info
                Write-ColorOutput "  Components: $($selectedProfile.Components.Count) monitoring scripts will run" -Color $Colors.Info
                return $selectedProfile.Name
            } elseif ($selectionNum -eq 5) {
                Write-ColorOutput "`n[+] Individual Component Selection" -Color $Colors.Success
                return Show-ComponentSelectionMenu -MonitoringComponents $MonitoringComponents
            } elseif ($selectionNum -eq 6) {
                Write-ColorOutput "`nMonitoring cancelled by user" -Color $Colors.Info
                exit 0
            } else {
                Write-ColorOutput "`n[!] Invalid selection. Please choose a number between 1 and 6" -Color $Colors.Error
            }
        } else {
            Write-ColorOutput "`n[!] Please enter a valid number" -Color $Colors.Error
        }
    } while ($true)
}

function Show-ComponentSelectionMenu {
    param([hashtable]$MonitoringComponents)
    
    Write-ColorOutput "`n$('='*60)" -Color $Colors.Header
    Write-ColorOutput "   INDIVIDUAL COMPONENT SELECTION" -Color $Colors.Header
    Write-ColorOutput $('='*60) -Color $Colors.Header
    
    $availableComponents = @()
    $index = 1
    
    foreach ($componentName in $MonitoringComponents.Keys | Sort-Object) {
        $component = $MonitoringComponents[$componentName]
        $availableComponents += @{
            Index = $index
            Name = $componentName
            Component = $component
        }
        
        $authRequired = if ($component.RequiresAuth) { " (requires authentication)" } else { "" }
        $essential = if ($component.Essential) { " [Essential]" } else { " [Optional]" }
        
        Write-ColorOutput "`n  [$index] $($component.Description)$essential" -Color $(if ($component.Essential) { $Colors.Success } else { $Colors.Warning })
        Write-ColorOutput "      Script: $($component.ScriptName)" -Color $Colors.Info
        Write-ColorOutput "      KPIs: $($component.KPICategories -join ', ')$authRequired" -Color $Colors.Progress
        
        $index++
    }
    
    Write-ColorOutput "`n  [$index] Select All Essential Components" -Color $Colors.Success
    Write-ColorOutput "      Run all essential monitoring components" -Color $Colors.Info
    
    $allIndex = $index + 1
    Write-ColorOutput "`n  [$allIndex] Select All Components" -Color $Colors.Warning
    Write-ColorOutput "      Run complete monitoring suite" -Color $Colors.Info
    
    $backIndex = $allIndex + 1
    Write-ColorOutput "`n  [$backIndex] Back to Main Menu" -Color $Colors.Info
    Write-ColorOutput "      Return to monitoring mode selection" -Color $Colors.Info
    
    Write-ColorOutput "`n$('-'*60)" -Color $Colors.Header
    Write-ColorOutput "Enter component numbers separated by commas (e.g., 1,2,4)" -Color $Colors.Info
    Write-ColorOutput "Or select a preset option" -Color $Colors.Info
    Write-ColorOutput $('-'*60) -Color $Colors.Header
    
    do {
        Write-ColorOutput "`nSelect components [1-$backIndex or comma-separated]: " -Color $Colors.Warning -NoNewline
        $selection = Read-Host
        
        # Handle single number selections
        if ($selection -match '^\d+$') {
            $selectionNum = [int]$selection
            
            if ($selectionNum -ge 1 -and $selectionNum -le $availableComponents.Count) {
                $selectedComponent = $availableComponents[$selectionNum - 1]
                Write-ColorOutput "`n[+] Selected: $($selectedComponent.Component.Description)" -Color $Colors.Success
                # Force return as array using Write-Output -NoEnumerate
                $result = @($selectedComponent.Name)
                Write-Output $result -NoEnumerate
                return
            } elseif ($selectionNum -eq $index) {
                Write-ColorOutput "`n[+] Selected: All Essential Components" -Color $Colors.Success
                return "Essential"
            } elseif ($selectionNum -eq $allIndex) {
                Write-ColorOutput "`n[+] Selected: All Components" -Color $Colors.Success
                return "Full"
            } elseif ($selectionNum -eq $backIndex) {
                return Show-MonitoringMenu -MonitoringComponents $MonitoringComponents
            } else {
                Write-ColorOutput "`n[!] Invalid selection. Please choose a number between 1 and $backIndex" -Color $Colors.Error
            }
        }
        # Handle comma-separated selections
        elseif ($selection -match '^[\d,\s]+$') {
            $numbers = $selection -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }
            $validNumbers = $numbers | Where-Object { $_ -ge 1 -and $_ -le $availableComponents.Count }
            
            if ($validNumbers.Count -gt 0) {
                $selectedComponents = $validNumbers | ForEach-Object {
                    $availableComponents[$_ - 1].Name
                }
                
                $selectedDescriptions = $validNumbers | ForEach-Object {
                    $availableComponents[$_ - 1].Component.Description
                }
                
                Write-ColorOutput "`n[+] Selected Components ($($selectedComponents.Count)):" -Color $Colors.Success
                foreach ($desc in $selectedDescriptions) {
                    Write-ColorOutput "  • $desc" -Color $Colors.Info
                }
                
                # Use Write-Output -NoEnumerate to preserve array structure
                Write-Output $selectedComponents -NoEnumerate
                return
            } else {
                Write-ColorOutput "`n[!] No valid component numbers found in selection" -Color $Colors.Error
            }
        } else {
            Write-ColorOutput "`n[!] Please enter valid numbers (single number or comma-separated)" -Color $Colors.Error
        }
    } while ($true)
}

# Define monitoring components
$MonitoringComponents = @{
    "PolicyActivity" = @{
        ScriptName = "Check-DLPPolicyActivity.ps1"
        Description = "DLP Policy Activity Analysis"
        Essential = $true
        RequiresAuth = $true
        KPICategories = @("Policy Coverage", "Match Rate", "Enforcement Rate")
    }
    "EndpointPerformance" = @{
        ScriptName = "Check-DLPEndpointPerformance.ps1"
        Description = "Endpoint Performance Impact"
        Essential = $true
        RequiresAuth = $false
        KPICategories = @("CPU Impact", "Memory Usage", "Disk I/O")
    }
    "FileLatency" = @{
        ScriptName = "Check-DLPFileAppLatency.ps1"
        Description = "File Operation Latency"
        Essential = $true
        RequiresAuth = $false
        KPICategories = @("File Open Delay", "Save Delay", "Copy/Move Delay")
    }
    "NetworkImpact" = @{
        ScriptName = "Check-DLPNetworkImpact.ps1"
        Description = "Network Performance Impact"
        Essential = $false
        RequiresAuth = $false
        KPICategories = @("Network Overhead", "Upload Delay", "Sync Impact")
    }
    "UserExperience" = @{
        ScriptName = "Check-DLPUserExperience.ps1"
        Description = "User Experience Monitoring"
        Essential = $false
        RequiresAuth = $false
        KPICategories = @("User Satisfaction", "Workflow Disruption", "Training Effectiveness")
    }
    "EventLogs" = @{
        ScriptName = "Check-DLPEventLogs.ps1"
        Description = "Event Log Analysis"
        Essential = $true
        RequiresAuth = $false
        KPICategories = @("Error Rate", "Warning Rate", "Agent Health")
    }
}

# Define monitoring mode configurations
$MonitoringConfigurations = @{
    "Full" = @("PolicyActivity", "EndpointPerformance", "FileLatency", "NetworkImpact", "UserExperience", "EventLogs")
    "Essential" = @("PolicyActivity", "EndpointPerformance", "FileLatency", "EventLogs")
    "Performance" = @("EndpointPerformance", "FileLatency", "NetworkImpact")
    "Policy" = @("PolicyActivity", "EventLogs")
}

Write-ColorOutput $('='*80) -Color $Colors.Header
Write-ColorOutput "MASTER DLP MONITORING SUITE" -Color $Colors.Header
Write-ColorOutput "Version: $script:scriptVersion | Author: $script:scriptAuthor" -Color $Colors.Header
Write-ColorOutput $('='*80) -Color $Colors.Header

# Show menu if no monitoring mode is specified and not skipping menu
if ([string]::IsNullOrEmpty($MonitoringMode) -and -not $SkipMenu) {
    $selectedMode = Show-MonitoringMenu -MonitoringComponents $MonitoringComponents
    
    # Handle individual component selection
    if ($selectedMode -is [array]) {
        # Custom component selection - selectedMode is an array of component names
        $selectedComponents = $selectedMode
        $MonitoringMode = "Custom"
        Write-ColorOutput "`nUsing custom component selection: $($selectedComponents -join ', ')" -Color $Colors.Info
    } elseif ($selectedMode -in @("Full", "Essential", "Performance", "Policy")) {
        # Standard monitoring mode
        $MonitoringMode = $selectedMode
    } else {
        # This shouldn't happen, but handle gracefully
        Write-ColorOutput "`nERROR: Unexpected menu result: $selectedMode" -Color $Colors.Error
        Write-ColorOutput "Type: $($selectedMode.GetType().Name), Value: '$selectedMode'" -Color $Colors.Info
        Write-ColorOutput "This appears to be a component name that wasn't properly wrapped as an array." -Color $Colors.Info
        Write-ColorOutput "Treating as custom component selection..." -Color $Colors.Warning
        
        # Handle single component as custom selection
        $selectedComponents = @($selectedMode)
        $MonitoringMode = "Custom"
        Write-ColorOutput "Using custom component selection: $selectedMode" -Color $Colors.Info
    }
} elseif ([string]::IsNullOrEmpty($MonitoringMode)) {
    # Default to Essential if no mode specified and skipping menu
    $MonitoringMode = "Essential"
    Write-ColorOutput "`nNo monitoring mode specified - defaulting to Essential mode" -Color $Colors.Info
}

# Validate MonitoringMode parameter
$validModes = @("Full", "Essential", "Performance", "Policy", "Custom")
if ($MonitoringMode -notin $validModes) {
    Write-ColorOutput "`nERROR: Invalid monitoring mode '$MonitoringMode'" -Color $Colors.Error
    Write-ColorOutput "Valid modes: $($validModes -join ', ')" -Color $Colors.Info
    exit 1
}

Write-ColorOutput "`nMonitoring Configuration:" -Color $Colors.Info
Write-ColorOutput "  Mode: $MonitoringMode" -Color $Colors.Info
Write-ColorOutput "  Duration: $Duration minutes" -Color $Colors.Info
Write-ColorOutput "  Script Directory: $ScriptDirectory" -Color $Colors.Info
Write-ColorOutput "  Quick Test: $(if ($QuickTest) { 'Yes' } else { 'No' })" -Color $Colors.Info
Write-ColorOutput "  Export Reports: $(if ($ExportReports) { 'Yes' } else { 'No' })" -Color $Colors.Info

try {
    # Validate script directory and components
    Write-ColorOutput "`nValidating monitoring components..." -Color $Colors.Progress
    
    # Determine which components to run
    if ($MonitoringMode -eq "Custom" -and (Get-Variable -Name "selectedComponents" -ErrorAction SilentlyContinue)) {
        $componentsToRun = $selectedComponents
    } else {
        $componentsToRun = $MonitoringConfigurations[$MonitoringMode]
    }
    
    if (-not $componentsToRun) {
        throw "Invalid monitoring mode: $MonitoringMode"
    }
    
    $availableComponents = @()
    $missingComponents = @()
    
    foreach ($componentName in $componentsToRun) {
        if (-not $MonitoringComponents.ContainsKey($componentName)) {
            Write-ColorOutput "  [-] Unknown component: $componentName" -Color $Colors.Error
            continue
        }
        
        $component = $MonitoringComponents[$componentName]
        $scriptPath = Join-Path $ScriptDirectory $component.ScriptName
        
        if (Test-Path $scriptPath) {
            $availableComponents += $componentName
            Write-ColorOutput "  [+] $($component.Description) - Available" -Color $Colors.Success
        } else {
            $missingComponents += $componentName
            Write-ColorOutput "  [-] $($component.Description) - Missing ($($component.ScriptName))" -Color $Colors.Warning
        }
    }
    
    if ($missingComponents.Count -gt 0) {
        Write-ColorOutput "`nWARNING: $($missingComponents.Count) monitoring components are missing" -Color $Colors.Warning
        Write-ColorOutput "Missing scripts: $($missingComponents -join ', ')" -Color $Colors.Warning
        Write-ColorOutput "Continuing with available components..." -Color $Colors.Info
    }
    
    if ($availableComponents.Count -eq 0) {
        throw "No monitoring components found in $ScriptDirectory"
    }
    
    # Validate authentication requirements
    if ($availableComponents -contains "PolicyActivity" -and -not $UserPrincipalName) {
        Write-ColorOutput "`nWARNING: PolicyActivity requires UserPrincipalName parameter" -Color $Colors.Warning
        Write-ColorOutput "Skipping Policy Activity monitoring..." -Color $Colors.Warning
        $availableComponents = $availableComponents | Where-Object { $_ -ne "PolicyActivity" }
    }
    
    Write-ColorOutput "`nExecuting DLP monitoring suite..." -Color $Colors.Progress
    Write-ColorOutput "Components to run: $($availableComponents.Count)" -Color $Colors.Info
    
    $monitoringResults = @{}
    $allKPIResults = @()
    $executionSummary = @{
        StartTime = Get-Date
        TotalComponents = $availableComponents.Count
        SuccessfulComponents = 0
        FailedComponents = 0
        ComponentResults = @{}
    }
    
    # Execute each monitoring component
    foreach ($componentName in $availableComponents) {
        $component = $MonitoringComponents[$componentName]
        $scriptPath = Join-Path $ScriptDirectory $component.ScriptName
        
        Write-ColorOutput "`n" + $('-'*60) -Color $Colors.Header
        Write-ColorOutput "EXECUTING: $($component.Description)" -Color $Colors.Header
        Write-ColorOutput $('-'*60) -Color $Colors.Header
        
        try {
            $startTime = Get-Date
            
            # Build script parameters
            $scriptParams = @{}
            
            # Common parameters
            if ($QuickTest) { $scriptParams.Add('QuickTest', $true) }
            if ($ExportReports) { $scriptParams.Add('ExportReports', $true) }
            
            # Component-specific parameters
            switch ($componentName) {
                "PolicyActivity" {
                    if ($UserPrincipalName) {
                        $scriptParams.Add('UserPrincipalName', $UserPrincipalName)
                    }
                }
                "EndpointPerformance" {
                    $scriptParams.Add('Duration', $Duration)
                }
                "FileLatency" {
                    if ($QuickTest) {
                        $scriptParams.Add('TestFileCount', 5)
                    }
                }
                "UserExperience" {
                    if ($IncludeUserSurvey) {
                        $scriptParams.Add('CollectSurveyData', $true)
                    }
                }
            }
            
            # Execute the script
            Write-ColorOutput "Starting $($component.ScriptName)..." -Color $Colors.Progress
            
            $scriptOutput = & $scriptPath @scriptParams 2>&1
            $exitCode = $LASTEXITCODE
            
            $endTime = Get-Date
            $duration = ($endTime - $startTime).TotalSeconds
            
            if ($exitCode -eq 0 -or $null -eq $exitCode) {
                Write-ColorOutput "[+] Completed successfully in $([math]::Round($duration, 1)) seconds" -Color $Colors.Success
                $executionSummary.SuccessfulComponents++
                
                $executionSummary.ComponentResults[$componentName] = @{
                    Status = "Success"
                    Duration = $duration
                    Output = $scriptOutput
                }
            } else {
                Write-ColorOutput "[-] Failed with exit code $exitCode" -Color $Colors.Error
                $executionSummary.FailedComponents++
                
                $executionSummary.ComponentResults[$componentName] = @{
                    Status = "Failed"
                    Duration = $duration
                    ExitCode = $exitCode
                    Output = $scriptOutput
                }
            }
            
            # Extract KPI information from output (simplified parsing)
            $kpiData = @{
                Component = $componentName
                Description = $component.Description
                Status = if ($exitCode -eq 0 -or $null -eq $exitCode) { "Success" } else { "Failed" }
                Duration = $duration
                Categories = $component.KPICategories
                Timestamp = Get-Date
            }
            
            $allKPIResults += $kpiData
            
        } catch {
            Write-ColorOutput "[-] Error executing $($component.ScriptName): $($_.Exception.Message)" -Color $Colors.Error
            $executionSummary.FailedComponents++
            
            $executionSummary.ComponentResults[$componentName] = @{
                Status = "Error"
                Duration = 0
                Error = $_.Exception.Message
            }
        }
    }
    
    $executionSummary.EndTime = Get-Date
    $executionSummary.TotalDuration = ($executionSummary.EndTime - $executionSummary.StartTime).TotalMinutes
    
    # Display execution summary
    Write-ColorOutput "`n" + $('='*60) -Color $Colors.Header
    Write-ColorOutput "MONITORING SUITE EXECUTION SUMMARY" -Color $Colors.Header
    Write-ColorOutput $('='*60) -Color $Colors.Header
    
    Write-ColorOutput "`nExecution Results:" -Color $Colors.Info
    Write-ColorOutput "  Total Components: $($executionSummary.TotalComponents)" -Color $Colors.Info
    Write-ColorOutput "  Successful: $($executionSummary.SuccessfulComponents)" -Color $Colors.Success
    Write-ColorOutput "  Failed: $($executionSummary.FailedComponents)" -Color $(if ($executionSummary.FailedComponents -gt 0) { $Colors.Error } else { $Colors.Success })
    Write-ColorOutput "  Total Duration: $([math]::Round($executionSummary.TotalDuration, 1)) minutes" -Color $Colors.Info
    
    # Component-by-component results
    Write-ColorOutput "`nComponent Results:" -Color $Colors.Info
    foreach ($componentName in $executionSummary.ComponentResults.Keys) {
        $result = $executionSummary.ComponentResults[$componentName]
        $component = $MonitoringComponents[$componentName]
        
        $statusColor = switch ($result.Status) {
            "Success" { $Colors.Success }
            "Failed" { $Colors.Error }
            "Error" { $Colors.Error }
            default { $Colors.Warning }
        }
        
        Write-ColorOutput "  $($component.Description):" -Color $Colors.Info
        Write-ColorOutput "    Status: $($result.Status)" -Color $statusColor
        Write-ColorOutput "    Duration: $([math]::Round($result.Duration, 1)) seconds" -Color $Colors.Info
        
        if ($result.ExitCode) {
            Write-ColorOutput "    Exit Code: $($result.ExitCode)" -Color $Colors.Error
        }
        
        if ($result.Error) {
            Write-ColorOutput "    Error: $($result.Error)" -Color $Colors.Error
        }
    }
    
    # Overall health assessment
    $successRate = [math]::Round($executionSummary.SuccessfulComponents / $executionSummary.TotalComponents * 100, 1)
    $overallStatus = if ($successRate -eq 100) { "Healthy" } elseif ($successRate -ge 80) { "Warning" } else { "Critical" }
    $overallColor = if ($successRate -eq 100) { $Colors.Success } elseif ($successRate -ge 80) { $Colors.Warning } else { $Colors.Error }
    
    Write-ColorOutput "`n[+] Overall Monitoring Health: $overallStatus ($successRate% success rate)" -Color $overallColor
    
    # Export consolidated reports
    if ($ExportReports) {
        Write-ColorOutput "`nExporting consolidated reports..." -Color $Colors.Progress
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        
        # Execution summary report
        $executionReport = [PSCustomObject]@{
            Timestamp = $executionSummary.StartTime
            Monitoring_Mode = $MonitoringMode
            Total_Components = $executionSummary.TotalComponents
            Successful_Components = $executionSummary.SuccessfulComponents
            Failed_Components = $executionSummary.FailedComponents
            Success_Rate_Percentage = $successRate
            Total_Duration_Minutes = [math]::Round($executionSummary.TotalDuration, 1)
            Overall_Status = $overallStatus
            Quick_Test_Mode = $QuickTest
            User_Survey_Included = $IncludeUserSurvey
            Script_Version = $script:scriptVersion
        }
        
        $executionCsvPath = "DLP_Master_Execution_Summary_$timestamp.csv"
        $executionReport | Export-Csv -Path $executionCsvPath -NoTypeInformation -Encoding UTF8
        Write-ColorOutput "  [+] Execution summary: $executionCsvPath" -Color $Colors.Success
        
        # Component details report
        $componentDetails = @()
        foreach ($componentName in $executionSummary.ComponentResults.Keys) {
            $result = $executionSummary.ComponentResults[$componentName]
            $component = $MonitoringComponents[$componentName]
            
            $componentDetails += [PSCustomObject]@{
                Component_Name = $componentName
                Script_Name = $component.ScriptName
                Description = $component.Description
                Status = $result.Status
                Duration_Seconds = [math]::Round($result.Duration, 1)
                Exit_Code = if ($result.ExitCode) { $result.ExitCode } else { "N/A" }
                Error_Message = if ($result.Error) { $result.Error } else { "N/A" }
                KPI_Categories = $component.KPICategories -join "; "
                Essential_Component = $component.Essential
                Requires_Authentication = $component.RequiresAuth
            }
        }
        
        $componentCsvPath = "DLP_Master_Component_Details_$timestamp.csv"
        $componentDetails | Export-Csv -Path $componentCsvPath -NoTypeInformation -Encoding UTF8
        Write-ColorOutput "  [+] Component details: $componentCsvPath" -Color $Colors.Success
        
        # KPI overview report
        $kpiOverview = [PSCustomObject]@{
            Timestamp = Get-Date
            Monitoring_Mode = $MonitoringMode
            Components_Executed = $availableComponents.Count
            Policy_Coverage_Checked = $availableComponents -contains "PolicyActivity"
            Performance_Impact_Measured = $availableComponents -contains "EndpointPerformance"
            Latency_Impact_Measured = $availableComponents -contains "FileLatency"
            Network_Impact_Measured = $availableComponents -contains "NetworkImpact"
            User_Experience_Measured = $availableComponents -contains "UserExperience"
            Event_Logs_Analysed = $availableComponents -contains "EventLogs"
            Overall_Health_Status = $overallStatus
            Success_Rate = "$successRate%"
            Recommendations = if ($executionSummary.FailedComponents -gt 0) { "Review failed components and address issues" } else { "All components executed successfully" }
        }
        
        $kpiOverviewCsvPath = "DLP_Master_KPI_Overview_$timestamp.csv"
        $kpiOverview | Export-Csv -Path $kpiOverviewCsvPath -NoTypeInformation -Encoding UTF8
        Write-ColorOutput "  [+] KPI overview: $kpiOverviewCsvPath" -Color $Colors.Success
    }
    
    # Provide recommendations
    Write-ColorOutput "`nRecommendations:" -Color $Colors.Header
    
    if ($executionSummary.FailedComponents -eq 0) {
        Write-ColorOutput "  [+] All monitoring components executed successfully" -Color $Colors.Success
        Write-ColorOutput "      Continue regular monitoring schedule" -Color $Colors.Info
        Write-ColorOutput "      Review individual component reports for detailed KPI analysis" -Color $Colors.Info
    } else {
        Write-ColorOutput "  [!] $($executionSummary.FailedComponents) components failed execution" -Color $Colors.Warning
        Write-ColorOutput "      Review component errors and resolve issues" -Color $Colors.Info
        Write-ColorOutput "      Ensure all required parameters are provided" -Color $Colors.Info
        Write-ColorOutput "      Verify script dependencies and permissions" -Color $Colors.Info
    }
    
    if ($missingComponents.Count -gt 0) {
        Write-ColorOutput "  [!] Missing components detected:" -Color $Colors.Warning
        foreach ($missingComp in $missingComponents) {
            Write-ColorOutput "      - $($MonitoringComponents[$missingComp].Description)" -Color $Colors.Info
        }
        Write-ColorOutput "      Ensure all monitoring scripts are present in $ScriptDirectory" -Color $Colors.Info
    }
    
    # Scheduling recommendations
    Write-ColorOutput "`nScheduling Recommendations:" -Color $Colors.Header
    switch ($MonitoringMode) {
        "Full" {
            Write-ColorOutput "  [+] Run full monitoring suite weekly or bi-weekly" -Color $Colors.Info
            Write-ColorOutput "      Use 'Essential' mode for daily monitoring" -Color $Colors.Info
        }
        "Essential" {
            Write-ColorOutput "  [+] Run essential monitoring daily or every few days" -Color $Colors.Info
            Write-ColorOutput "      Suitable for continuous monitoring" -Color $Colors.Info
        }
        "Performance" {
            Write-ColorOutput "  [+] Run performance monitoring during high-usage periods" -Color $Colors.Info
            Write-ColorOutput "      Use when investigating performance issues" -Color $Colors.Info
        }
        "Policy" {
            Write-ColorOutput "  [+] Run policy monitoring after DLP policy changes" -Color $Colors.Info
            Write-ColorOutput "      Use for compliance reporting" -Color $Colors.Info
        }
        "Custom" {
            Write-ColorOutput "  [+] Custom component monitoring completed" -Color $Colors.Info
            Write-ColorOutput "      Schedule based on selected components" -Color $Colors.Info
        }
    }
    
    Write-ColorOutput "`n[+] Master DLP monitoring suite completed successfully" -Color $Colors.Success
    $selectedComponentsText = if ($MonitoringMode -eq 'Custom' -and (Get-Variable -Name "selectedComponents" -ErrorAction SilentlyContinue)) { 
        'Custom (' + ($selectedComponents -join ', ') + ')' 
    } else { 
        $MonitoringMode 
    }
    Write-ColorOutput "Monitoring configuration: $selectedComponentsText" -Color $Colors.Info
    
    # Return success code
    exit 0

} catch {
    Write-ColorOutput "`nERROR: $($_.Exception.Message)" -Color $Colors.Error
    Write-ColorOutput "Line: $($_.InvocationInfo.ScriptLineNumber)" -Color $Colors.Info
    
    Write-ColorOutput "`nTroubleshooting:" -Color $Colors.Warning
    Write-ColorOutput "  1. Verify all monitoring scripts are present in $ScriptDirectory" -Color $Colors.Info
    Write-ColorOutput "  2. Check script permissions and dependencies" -Color $Colors.Info
    Write-ColorOutput "  3. Ensure UserPrincipalName is provided for policy monitoring" -Color $Colors.Info
    Write-ColorOutput "  4. Run individual scripts to identify specific issues" -Color $Colors.Info
    
    exit 1
}

Write-ColorOutput "`n" + $('='*80) -Color $Colors.Header
Write-ColorOutput "END OF MASTER DLP MONITORING SUITE" -Color $Colors.Header
Write-ColorOutput $('='*80) -Color $Colors.Header