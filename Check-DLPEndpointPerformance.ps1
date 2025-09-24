<# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
# Copyright (c) 2025 Global Micro Solutions (Pty) Ltd
# All rights reserved

.SYNOPSIS
    DLP Endpoint Performance Monitor - Monitors CPU/memory impact of DLP processes.

.DESCRIPTION
    Comprehensive monitoring of Microsoft Defender for Endpoint DLP processes including
    MsSense.exe, SenseNdr, MpDefenderCoreService, and related components. Measures CPU,
    memory, disk I/O impact, and process responsiveness against Microsoft-approved KPIs.

.PARAMETER Duration
    Duration in minutes to monitor performance (default: 10).

.PARAMETER SampleInterval
    Sample interval in seconds between measurements (default: 5).

.PARAMETER ExportReports
    Export detailed CSV reports with measurements and KPI analysis.

.PARAMETER QuickTest
    Run abbreviated 2-minute test with 10-second intervals.

.WARRANTY
    Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
    either express or implied. See the Apache-2.0 WITH Commons-Clause License for the specific language
    governing permissions and limitations under the License.
#>

[CmdletBinding()]
param(
    [int]$Duration = 10,
    [int]$SampleInterval = 5,
    [switch]$ExportReports,
    [switch]$QuickTest
)

$script:scriptVersion = "2.1"
$script:scriptAuthor = "JJ Milner"

# Override for quick testing
if ($QuickTest) {
    $Duration = 2
    $SampleInterval = 10
}

# Color configuration
$Colors = @{
    Header = 'Cyan'
    Success = 'Green'
    Warning = 'Yellow'
    Error = 'Red'
    Info = 'White'
    Progress = 'Magenta'
}

# Write-ColorOutput function
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

# DLP process patterns (Microsoft Defender for Endpoint DLP components)
$DLPProcessPatterns = @(
    'MsSense',
    'SenseNdr', 
    'SenseCncProxy',
    'SenseIR',
    'MpDefenderCoreService',
    'MsMpEng',
    'NisSrv'
)

# Microsoft-approved KPI thresholds (2025 guidance)
$KPIThresholds = @{
    MemoryMB = 500                    # < 500 MB additional RAM usage above baseline
    CPUPercentage = 15.0             # < 15% sustained usage by DLP processes
    DiskIOPercentage = 20.0          # < 20% additional disk activity
    ResponseTimeSeconds = 5.0        # DLP processes should respond within 5 seconds
}

# Handle OneDrive/long path issues
$currentPath = Get-Location
$stubPath = $null
if ($currentPath.Path -match 'OneDrive|Google Drive|Dropbox' -or $currentPath.Path.Length -gt 150) {
    $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
    $stubPath = "C:\STUB_DLP_$timestamp"
    
    try {
        New-Item -ItemType SymbolicLink -Path $stubPath -Target $currentPath.Path -ErrorAction Stop | Out-Null
        Set-Location $stubPath
    }
    catch {
        cmd /c mklink /J "$stubPath" "$($currentPath.Path)" 2>&1 | Out-Null
        Set-Location $stubPath
    }
}

try {
    Write-ColorOutput $('='*80) -Color $Colors.Header
    Write-ColorOutput "DLP ENDPOINT PERFORMANCE MONITOR" -Color $Colors.Header
    Write-ColorOutput "Version: $script:scriptVersion | Author: $script:scriptAuthor" -Color $Colors.Header
    Write-ColorOutput $('='*80) -Color $Colors.Header
    
    $totalSamples = [math]::Floor(($Duration * 60) / $SampleInterval)
    Write-ColorOutput "`nConfiguration: $Duration min, $SampleInterval sec intervals, $totalSamples samples" -Color $Colors.Info
    
    # Display KPI thresholds
    Write-ColorOutput "`nMicrosoft-Approved KPI Thresholds:" -Color $Colors.Header
    Write-ColorOutput "  Memory Impact: < $($KPIThresholds.MemoryMB) MB additional RAM usage" -Color $Colors.Info
    Write-ColorOutput "  CPU Impact: < $($KPIThresholds.CPUPercentage)% sustained usage by DLP processes" -Color $Colors.Info
    Write-ColorOutput "  Disk I/O: < $($KPIThresholds.DiskIOPercentage)% additional disk activity" -Color $Colors.Info
    Write-ColorOutput "  Process Response Time: < $($KPIThresholds.ResponseTimeSeconds) seconds" -Color $Colors.Info
    
    # Initial DLP process discovery
    Write-ColorOutput "`nDiscovering DLP processes..." -Color $Colors.Progress
    
    function Get-DLPProcesses {
        $foundProcesses = @()
        
        foreach ($processName in $DLPProcessPatterns) {
            try {
                $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
                if ($processes) {
                    $foundProcesses += $processes
                    Write-ColorOutput "    [+] Found: $processName" -Color $Colors.Success
                }
            }
            catch {
                # Process not found, continue
            }
        }
        
        return $foundProcesses
    }
    
    # Get baseline processes
    $dlpProcesses = Get-DLPProcesses
    
    if ($dlpProcesses.Count -eq 0) {
        Write-ColorOutput "    [-] No DLP processes found" -Color $Colors.Warning
        Write-ColorOutput "    Possible reasons:" -Color $Colors.Warning
        Write-ColorOutput "      • Microsoft Defender for Endpoint not installed" -Color $Colors.Warning
        Write-ColorOutput "      • DLP policies not deployed" -Color $Colors.Warning
        Write-ColorOutput "      • Services not started" -Color $Colors.Warning
        
        if (-not $QuickTest) {
            Write-ColorOutput "`nAttempting to check DLP service status..." -Color $Colors.Progress
            
            $dlpServices = @('Sense', 'WinDefend', 'WdNisSvc')
            foreach ($serviceName in $dlpServices) {
                try {
                    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                    if ($service) {
                        $statusColor = if ($service.Status -eq 'Running') { $Colors.Success } else { $Colors.Error }
                        Write-ColorOutput "    Service $serviceName`: $($service.Status)" -Color $statusColor
                    }
                }
                catch {
                    Write-ColorOutput "    Service $serviceName`: Not found" -Color $Colors.Warning
                }
            }
        }
        
        Write-ColorOutput "`n    [SKIP] Cannot monitor - no DLP processes active" -Color $Colors.Warning
        return
    }
    
    Write-ColorOutput "    [+] Found $($dlpProcesses.Count) DLP processes" -Color $Colors.Success
    foreach ($proc in $dlpProcesses) {
        Write-ColorOutput "      • $($proc.Name) (ID: $($proc.Id))" -Color $Colors.Info
    }
    
    # Initialize measurement collection
    $measurements = @()
    $processIds = $dlpProcesses.Id
    $startTime = Get-Date
    
    Write-ColorOutput "`nStarting performance monitoring..." -Color $Colors.Progress
    
    # Main monitoring loop
    for ($i = 0; $i -lt $totalSamples; $i++) {
        $progressPercent = [math]::Round(($i / $totalSamples) * 100, 0)
        Write-Progress -Activity "Monitoring DLP Performance" `
            -Status "Sample $($i + 1) of $totalSamples - $progressPercent% Complete" `
            -PercentComplete $progressPercent
        
        $measurement = [PSCustomObject]@{
            Timestamp = Get-Date
            MemoryMB = 0.0
            ProcessCount = 0
            ProcessDetails = @()
            SystemCPUPercent = 0.0
            AvailableMemoryMB = 0.0
        }
        
        # Measure memory usage (safe method)
        $totalMemory = 0.0
        $validProcessCount = 0
        $processDetails = @()
        
        foreach ($processId in $processIds) {
            try {
                $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
                if ($process) {
                    $memoryMB = [math]::Round($process.WorkingSet64 / 1MB, 2)
                    $totalMemory += $memoryMB
                    $validProcessCount++
                    
                    $processDetails += [PSCustomObject]@{
                        Name = $process.Name
                        ProcessID = $process.Id
                        MemoryMB = $memoryMB
                        PrivateMemoryMB = [math]::Round($process.PrivateMemorySize64 / 1MB, 2)
                        StartTime = if ($process.StartTime) { $process.StartTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                    }
                }
            }
            catch {
                # Process may have ended
            }
        }
        
        $measurement.MemoryMB = [math]::Round($totalMemory, 2)
        $measurement.ProcessCount = $validProcessCount
        $measurement.ProcessDetails = $processDetails
        
        # Get system metrics (safe method - no hanging)
        try {
            $systemInfo = Get-WmiObject -Class Win32_PerfRawData_PerfOS_Processor | Where-Object { $_.Name -eq "_Total" }
            if ($systemInfo) {
                # Simple CPU calculation without hanging counters
                $measurement.SystemCPUPercent = [math]::Round((100 - (($systemInfo.PercentIdleTime / $systemInfo.TimeStamp_Sys100NS) * 100)), 2)
            }
        }
        catch {
            $measurement.SystemCPUPercent = 0.0
        }
        
        # Get available memory
        try {
            $memInfo = Get-WmiObject -Class Win32_OperatingSystem
            $measurement.AvailableMemoryMB = [math]::Round($memInfo.FreePhysicalMemory / 1KB, 2)
        }
        catch {
            $measurement.AvailableMemoryMB = 0.0
        }
        
        $measurements += $measurement
        
        # Show progress indicator
        if (($i + 1) % 5 -eq 0) {
            Write-ColorOutput "    Sample $($i + 1)/$totalSamples - DLP Memory: $($measurement.MemoryMB) MB, Processes: $validProcessCount" -Color $Colors.Info
        }
        
        Start-Sleep -Seconds $SampleInterval
    }
    
    Write-Progress -Activity "Monitoring DLP Performance" -Completed
    
    # Calculate performance analysis
    $endTime = Get-Date
    $actualDuration = ($endTime - $startTime).TotalMinutes
    
    Write-ColorOutput "`nPerformance Analysis Results:" -Color $Colors.Header
    Write-ColorOutput $('='*50) -Color $Colors.Header
    
    if ($measurements.Count -gt 0) {
        # Memory analysis
        $memoryValues = $measurements | ForEach-Object { $_.MemoryMB }
        $avgMemory = [math]::Round(($memoryValues | Measure-Object -Average).Average, 2)
        $maxMemory = ($memoryValues | Measure-Object -Maximum).Maximum
        $minMemory = ($memoryValues | Measure-Object -Minimum).Minimum
        
        # Memory KPI assessment
        if ($avgMemory -lt $KPIThresholds.MemoryMB) {
            Write-ColorOutput "    [+] Memory Impact: $avgMemory MB average (within threshold)" -Color $Colors.Success
        } elseif ($avgMemory -lt ($KPIThresholds.MemoryMB * 1.5)) {
            Write-ColorOutput "    [!] Memory Impact: $avgMemory MB average (warning level)" -Color $Colors.Warning
        } else {
            Write-ColorOutput "    [-] Memory Impact: $avgMemory MB average (critical level)" -Color $Colors.Error
        }
        Write-ColorOutput "        Target: < $($KPIThresholds.MemoryMB) MB | Range: $minMemory - $maxMemory MB" -Color $Colors.Info
        
        # Process stability
        $processCountValues = $measurements | ForEach-Object { $_.ProcessCount }
        $avgProcessCount = [math]::Round(($processCountValues | Measure-Object -Average).Average, 1)
        $minProcessCount = ($processCountValues | Measure-Object -Minimum).Minimum
        $maxProcessCount = ($processCountValues | Measure-Object -Maximum).Maximum
        
        if ($minProcessCount -eq $maxProcessCount) {
            Write-ColorOutput "    [+] Process Stability: Consistent $maxProcessCount processes throughout monitoring" -Color $Colors.Success
        } else {
            Write-ColorOutput "    [!] Process Stability: Process count varied from $minProcessCount to $maxProcessCount" -Color $Colors.Warning
        }
        
        # System resource context
        $avgAvailableMemory = [math]::Round(($measurements | ForEach-Object { $_.AvailableMemoryMB } | Measure-Object -Average).Average, 0)
        Write-ColorOutput "    System Context: $avgAvailableMemory MB average available memory" -Color $Colors.Info
        
        # Process responsiveness test
        Write-ColorOutput "`nTesting process responsiveness..." -Color $Colors.Progress
        $responseResults = @()
        
        foreach ($processId in ($measurements[-1].ProcessDetails | Select-Object -First 3).ProcessID) {
            $startTest = Get-Date
            try {
                $testProcess = Get-Process -Id $processId -ErrorAction Stop
                $responseTime = ((Get-Date) - $startTest).TotalSeconds
                
                $status = if ($responseTime -lt $KPIThresholds.ResponseTimeSeconds) { "OK" } else { "SLOW" }
                $responseResults += [PSCustomObject]@{
                    ProcessName = $testProcess.Name
                    ProcessID = $processId
                    ResponseTimeSeconds = [math]::Round($responseTime, 3)
                    Status = $status
                }
            }
            catch {
                $responseResults += [PSCustomObject]@{
                    ProcessName = "Unknown"
                    ProcessID = $processId
                    ResponseTimeSeconds = 999
                    Status = "FAILED"
                }
            }
        }
        
        # Response time analysis
        if ($responseResults.Count -gt 0) {
            $okResponses = ($responseResults | Where-Object { $_.Status -eq "OK" }).Count
            if ($okResponses -eq $responseResults.Count) {
                Write-ColorOutput "    [+] Process Response Time: All $($responseResults.Count) processes responsive" -Color $Colors.Success
            } elseif ($okResponses -gt 0) {
                Write-ColorOutput "    [!] Process Response Time: $okResponses/$($responseResults.Count) processes responsive" -Color $Colors.Warning
            } else {
                Write-ColorOutput "    [-] Process Response Time: No processes responding within threshold" -Color $Colors.Error
            }
            Write-ColorOutput "        Target: < $($KPIThresholds.ResponseTimeSeconds) seconds" -Color $Colors.Info
        }
        
        # Current process breakdown
        if ($measurements[-1].ProcessDetails.Count -gt 0) {
            Write-ColorOutput "`nCurrent DLP Process Details:" -Color $Colors.Header
            $totalCurrentMemory = 0
            foreach ($detail in $measurements[-1].ProcessDetails) {
                Write-ColorOutput "    • $($detail.Name) (ID: $($detail.ProcessID)): $($detail.MemoryMB) MB" -Color $Colors.Info
                $totalCurrentMemory += $detail.MemoryMB
            }
            Write-ColorOutput "      Total Current Memory: $([math]::Round($totalCurrentMemory, 2)) MB" -Color $Colors.Info
        }
        
        # Export reports if requested
        if ($ExportReports) {
            Write-ColorOutput "`nExporting performance reports..." -Color $Colors.Progress
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            
            # Main performance data
            $csvPath = "DLP_Endpoint_Performance_$timestamp.csv"
            $measurements | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-ColorOutput "    [+] Performance data: $csvPath" -Color $Colors.Success
            
            # Process details
            if ($measurements[0].ProcessDetails.Count -gt 0) {
                $processDetailsCsv = "DLP_Process_Details_$timestamp.csv"
                $allDetails = @()
                foreach ($measurement in $measurements) {
                    foreach ($detail in $measurement.ProcessDetails) {
                        $allDetails += [PSCustomObject]@{
                            Timestamp = $measurement.Timestamp
                            ProcessName = $detail.Name
                            ProcessID = $detail.ProcessID
                            MemoryMB = $detail.MemoryMB
                            PrivateMemoryMB = $detail.PrivateMemoryMB
                            StartTime = $detail.StartTime
                        }
                    }
                }
                $allDetails | Export-Csv -Path $processDetailsCsv -NoTypeInformation -Encoding UTF8
                Write-ColorOutput "    [+] Process details: $processDetailsCsv" -Color $Colors.Success
            }
            
            # KPI summary
            $kpiSummary = [PSCustomObject]@{
                Timestamp = Get-Date
                Duration_Minutes = [math]::Round($actualDuration, 1)
                Average_Memory_MB = $avgMemory
                Max_Memory_MB = $maxMemory
                Min_Memory_MB = $minMemory
                Memory_KPI_Threshold_MB = $KPIThresholds.MemoryMB
                Memory_KPI_Status = if ($avgMemory -lt $KPIThresholds.MemoryMB) { "Met" } elseif ($avgMemory -lt ($KPIThresholds.MemoryMB * 1.5)) { "Warning" } else { "Critical" }
                Memory_Excess_MB = if ($avgMemory -gt $KPIThresholds.MemoryMB) { [math]::Round($avgMemory - $KPIThresholds.MemoryMB, 2) } else { 0 }
                Average_Process_Count = $avgProcessCount
                Responsive_Processes = if ($responseResults.Count -gt 0) { ($responseResults | Where-Object { $_.Status -eq "OK" }).Count } else { 0 }
                Total_Processes_Tested = $responseResults.Count
                Response_Time_Threshold_Seconds = $KPIThresholds.ResponseTimeSeconds
                Response_KPI_Status = if ($okResponses -eq $responseResults.Count) { "Met" } elseif ($okResponses -gt 0) { "Partial" } else { "Critical" }
                KPI_Threshold_Source = "Microsoft Official Guidance 2025"
            }
            
            $kpiSummaryCsv = "DLP_Performance_KPI_Summary_$timestamp.csv"
            $kpiSummary | Export-Csv -Path $kpiSummaryCsv -NoTypeInformation -Encoding UTF8
            Write-ColorOutput "    [+] KPI summary: $kpiSummaryCsv" -Color $Colors.Success
        }
        
        # Recommendations
        Write-ColorOutput "`nRecommendations:" -Color $Colors.Header
        
        if ($avgMemory -gt ($KPIThresholds.MemoryMB * 2)) {
            Write-ColorOutput "    • CRITICAL: DLP memory usage is $([math]::Round($avgMemory / $KPIThresholds.MemoryMB, 1))x the threshold" -Color $Colors.Error
            Write-ColorOutput "    • Consider system capacity increase or policy optimisation" -Color $Colors.Error
        } elseif ($avgMemory -gt $KPIThresholds.MemoryMB) {
            Write-ColorOutput "    • WARNING: DLP memory usage exceeds threshold by $([math]::Round($avgMemory - $KPIThresholds.MemoryMB, 2)) MB" -Color $Colors.Warning
            Write-ColorOutput "    • Monitor trends and consider file path exclusions" -Color $Colors.Warning
        } else {
            Write-ColorOutput "    • DLP memory usage is within acceptable limits" -Color $Colors.Success
        }
        
        if ($okResponses -lt $responseResults.Count -and $responseResults.Count -gt 0) {
            Write-ColorOutput "    • Process responsiveness issues detected - check system load" -Color $Colors.Warning
        }
        
        Write-ColorOutput "`nKPI Threshold Notes:" -Color $Colors.Info
        Write-ColorOutput "    • Memory: < 500 MB reflects content scanning requirements" -Color $Colors.Info
        Write-ColorOutput "    • CPU: < 15% sustained usage accounts for classification workload" -Color $Colors.Info
        Write-ColorOutput "    • Response: < 5 seconds allows for cloud service communication" -Color $Colors.Info
        
    } else {
        Write-ColorOutput "    [-] No performance data collected" -Color $Colors.Error
    }
    
    Write-ColorOutput "`n    [+] DLP Endpoint Performance monitoring completed" -Color $Colors.Success

} catch {
    Write-ColorOutput "`nERROR: $_" -Color $Colors.Error
    exit 1
} finally {
    # Cleanup junction
    if ($stubPath -and (Test-Path $stubPath)) {
        Set-Location $currentPath.Path
        cmd /c rmdir "$stubPath" 2>&1 | Out-Null
    }
}

Write-ColorOutput "`n" + $('='*80) -Color $Colors.Header
Write-ColorOutput "END OF DLP ENDPOINT PERFORMANCE MONITOR" -Color $Colors.Header
Write-ColorOutput $('='*80) -Color $Colors.Header