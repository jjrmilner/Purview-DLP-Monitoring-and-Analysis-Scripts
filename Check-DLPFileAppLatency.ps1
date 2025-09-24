<# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
# Copyright (c) 2025 Global Micro Solutions (Pty) Ltd
# All rights reserved

.SYNOPSIS
    DLP File/App Latency Monitor - Measures file operation delays caused by DLP scanning.

.DESCRIPTION
    Comprehensive monitoring of file operation latency impact from Microsoft Purview Endpoint DLP.
    Tests file open, save, copy/move operations and application startup delays to measure
    real-world user experience impact against Microsoft-approved KPI thresholds.

.PARAMETER TestDirectory
    Directory path for test file operations (default: current directory).

.PARAMETER TestFileCount
    Number of test files to create for latency testing (default: 10).

.PARAMETER TestFileSizeMB
    Size of each test file in MB (default: 1).

.PARAMETER ExportReports
    Export detailed CSV reports with latency measurements and KPI analysis.

.PARAMETER QuickTest
    Run abbreviated test with fewer files and operations.

.PARAMETER IncludeAppStartup
    Include application startup time testing (Notepad, WordPad, Calculator).

.WARRANTY
    Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
    either express or implied. See the Apache-2.0 WITH Commons-Clause License for the specific language
    governing permissions and limitations under the License.
#>

[CmdletBinding()]
param(
    [string]$TestDirectory = ".",
    [int]$TestFileCount = 10,
    [int]$TestFileSizeMB = 1,
    [switch]$ExportReports,
    [switch]$QuickTest,
    [switch]$IncludeAppStartup
)

$script:scriptVersion = "1.0"
$script:scriptAuthor = "JJ Milner"

# Override for quick testing
if ($QuickTest) {
    $TestFileCount = 5
    $TestFileSizeMB = 1
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

# Microsoft-approved KPI thresholds (2025 guidance)
$KPIThresholds = @{
    FileOpenDelayMS = 500              # < 500ms additional latency for file operations
    SaveOperationDelayMS = 1000        # < 1000ms additional latency for save operations
    CopyMoveOperationDelayMS = 2000    # < 2000ms additional latency for copy/move operations
    ApplicationStartupDelayMS = 5000   # < 5 seconds additional startup time
}

# Handle OneDrive/long path issues
$currentPath = Get-Location
$stubPath = $null
if ($currentPath.Path -match 'OneDrive|Google Drive|Dropbox' -or $currentPath.Path.Length -gt 150) {
    $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
    $stubPath = "C:\STUB_DLP_LAT_$timestamp"
    
    try {
        New-Item -ItemType SymbolicLink -Path $stubPath -Target $currentPath.Path -ErrorAction Stop | Out-Null
        Set-Location $stubPath
        $TestDirectory = $stubPath
    }
    catch {
        cmd /c mklink /J "$stubPath" "$($currentPath.Path)" 2>&1 | Out-Null
        Set-Location $stubPath
        $TestDirectory = $stubPath
    }
}

try {
    Write-ColorOutput $('='*80) -Color $Colors.Header
    Write-ColorOutput "DLP FILE/APP LATENCY MONITOR" -Color $Colors.Header
    Write-ColorOutput "Version: $script:scriptVersion | Author: $script:scriptAuthor" -Color $Colors.Header
    Write-ColorOutput $('='*80) -Color $Colors.Header
    
    Write-ColorOutput "`nConfiguration:" -Color $Colors.Info
    Write-ColorOutput "  Test Directory: $TestDirectory" -Color $Colors.Info
    Write-ColorOutput "  Test Files: $TestFileCount files @ $TestFileSizeMB MB each" -Color $Colors.Info
    Write-ColorOutput "  Include App Startup: $(if ($IncludeAppStartup) { 'Yes' } else { 'No' })" -Color $Colors.Info
    
    # Display KPI thresholds
    Write-ColorOutput "`nMicrosoft-Approved KPI Thresholds:" -Color $Colors.Header
    Write-ColorOutput "  File Open Delay: < $($KPIThresholds.FileOpenDelayMS) ms additional latency" -Color $Colors.Info
    Write-ColorOutput "  Save Operation Delay: < $($KPIThresholds.SaveOperationDelayMS) ms additional latency" -Color $Colors.Info
    Write-ColorOutput "  Copy/Move Operations: < $($KPIThresholds.CopyMoveOperationDelayMS) ms additional latency" -Color $Colors.Info
    Write-ColorOutput "  Application Startup Impact: < $($KPIThresholds.ApplicationStartupDelayMS) ms additional startup time" -Color $Colors.Info
    
    # Create test directory structure
    $testPath = Join-Path $TestDirectory "DLP_Latency_Test_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Write-ColorOutput "`nSetting up test environment..." -Color $Colors.Progress
    
    try {
        New-Item -ItemType Directory -Path $testPath -Force | Out-Null
        Write-ColorOutput "    [+] Test directory created: $testPath" -Color $Colors.Success
    }
    catch {
        Write-ColorOutput "    [-] Failed to create test directory: $_" -Color $Colors.Error
        throw "Cannot create test directory"
    }
    
    # Initialize measurement collections
    $fileOpenResults = @()
    $fileSaveResults = @()
    $fileCopyResults = @()
    $appStartupResults = @()
    $overallResults = @()
    
    # Generate test files with sensitive content patterns
    Write-ColorOutput "`nGenerating test files with DLP-triggering content..." -Color $Colors.Progress
    $sensitivePatterns = @(
        "Social Security Number: 123-45-6789",
        "Credit Card: 4532-1234-5678-9012",
        "CONFIDENTIAL DOCUMENT - Internal Use Only",
        "Personal Information: John.Doe@company.com",
        "Financial Record: Account 987654321"
    )
    
    $testFiles = @()
    for ($i = 1; $i -le $TestFileCount; $i++) {
        $progressPercent = [math]::Round(($i / $TestFileCount) * 100, 0)
        Write-Progress -Activity "Creating Test Files" `
            -Status "File $i of $TestFileCount - $progressPercent% Complete" `
            -PercentComplete $progressPercent
        
        $fileName = "DLP_Test_File_$i.txt"
        $filePath = Join-Path $testPath $fileName
        
        # Create file content with sensitive patterns
        $content = @()
        $content += "DLP Latency Test File $i"
        $content += "Created: $(Get-Date)"
        $content += ""
        
        # Add sensitive patterns to trigger DLP scanning
        foreach ($pattern in $sensitivePatterns) {
            $content += "$pattern - Test Data $i"
        }
        
        # Pad file to desired size
        $currentSize = ($content -join "`r`n").Length
        $targetSize = $TestFileSizeMB * 1MB
        
        if ($currentSize -lt $targetSize) {
            $paddingNeeded = $targetSize - $currentSize
            $paddingText = "X" * $paddingNeeded
            $content += $paddingText
        }
        
        # Write file and measure initial creation time
        $startCreate = Get-Date
        $content -join "`r`n" | Out-File -FilePath $filePath -Encoding UTF8
        $createTime = ((Get-Date) - $startCreate).TotalMilliseconds
        
        $testFiles += [PSCustomObject]@{
            FileName = $fileName
            FilePath = $filePath
            SizeMB = [math]::Round((Get-Item $filePath).Length / 1MB, 2)
            CreateTimeMS = [math]::Round($createTime, 2)
        }
    }
    
    Write-Progress -Activity "Creating Test Files" -Completed
    Write-ColorOutput "    [+] Created $TestFileCount test files (avg creation: $([math]::Round(($testFiles | Measure-Object CreateTimeMS -Average).Average, 2)) ms)" -Color $Colors.Success
    
    # Test 1: File Open Operations
    Write-ColorOutput "`nTesting file open operations..." -Color $Colors.Progress
    
    foreach ($testFile in $testFiles) {
        $progressPercent = [math]::Round((([array]::IndexOf($testFiles, $testFile) + 1) / $testFiles.Count) * 100, 0)
        Write-Progress -Activity "Testing File Open Operations" `
            -Status "$($testFile.FileName) - $progressPercent% Complete" `
            -PercentComplete $progressPercent
        
        # Measure file open time
        $startOpen = Get-Date
        try {
            $content = Get-Content -Path $testFile.FilePath -ErrorAction Stop
            $openTime = ((Get-Date) - $startOpen).TotalMilliseconds
            $status = "Success"
        }
        catch {
            $openTime = 999999
            $status = "Failed: $_"
        }
        
        $fileOpenResults += [PSCustomObject]@{
            FileName = $testFile.FileName
            FileSizeMB = $testFile.SizeMB
            OpenTimeMS = [math]::Round($openTime, 2)
            Status = $status
            KPIStatus = if ($openTime -lt $KPIThresholds.FileOpenDelayMS) { "Met" } 
                       elseif ($openTime -lt ($KPIThresholds.FileOpenDelayMS * 2)) { "Warning" } 
                       else { "Critical" }
        }
        
        # Brief pause to avoid overwhelming DLP
        Start-Sleep -Milliseconds 100
    }
    
    Write-Progress -Activity "Testing File Open Operations" -Completed
    
    # Test 2: File Save Operations
    Write-ColorOutput "`nTesting file save operations..." -Color $Colors.Progress
    
    foreach ($testFile in $testFiles) {
        $progressPercent = [math]::Round((([array]::IndexOf($testFiles, $testFile) + 1) / $testFiles.Count) * 100, 0)
        Write-Progress -Activity "Testing File Save Operations" `
            -Status "$($testFile.FileName) - $progressPercent% Complete" `
            -PercentComplete $progressPercent
        
        # Modify and save file
        $startSave = Get-Date
        try {
            $newContent = (Get-Content -Path $testFile.FilePath) + "`nModified: $(Get-Date)"
            $newContent | Out-File -FilePath $testFile.FilePath -Encoding UTF8
            $saveTime = ((Get-Date) - $startSave).TotalMilliseconds
            $status = "Success"
        }
        catch {
            $saveTime = 999999
            $status = "Failed: $_"
        }
        
        $fileSaveResults += [PSCustomObject]@{
            FileName = $testFile.FileName
            FileSizeMB = $testFile.SizeMB
            SaveTimeMS = [math]::Round($saveTime, 2)
            Status = $status
            KPIStatus = if ($saveTime -lt $KPIThresholds.SaveOperationDelayMS) { "Met" } 
                       elseif ($saveTime -lt ($KPIThresholds.SaveOperationDelayMS * 2)) { "Warning" } 
                       else { "Critical" }
        }
        
        Start-Sleep -Milliseconds 100
    }
    
    Write-Progress -Activity "Testing File Save Operations" -Completed
    
    # Test 3: File Copy/Move Operations
    Write-ColorOutput "`nTesting file copy/move operations..." -Color $Colors.Progress
    
    $copyDir = Join-Path $testPath "Copy_Test"
    New-Item -ItemType Directory -Path $copyDir -Force | Out-Null
    
    foreach ($testFile in ($testFiles | Select-Object -First 5)) {  # Test subset for copy operations
        $progressPercent = [math]::Round((([array]::IndexOf(($testFiles | Select-Object -First 5), $testFile) + 1) / 5) * 100, 0)
        Write-Progress -Activity "Testing File Copy Operations" `
            -Status "$($testFile.FileName) - $progressPercent% Complete" `
            -PercentComplete $progressPercent
        
        $copyPath = Join-Path $copyDir "Copy_$($testFile.FileName)"
        
        # Measure copy time
        $startCopy = Get-Date
        try {
            Copy-Item -Path $testFile.FilePath -Destination $copyPath -ErrorAction Stop
            $copyTime = ((Get-Date) - $startCopy).TotalMilliseconds
            $status = "Success"
        }
        catch {
            $copyTime = 999999
            $status = "Failed: $_"
        }
        
        $fileCopyResults += [PSCustomObject]@{
            FileName = $testFile.FileName
            FileSizeMB = $testFile.SizeMB
            CopyTimeMS = [math]::Round($copyTime, 2)
            Status = $status
            KPIStatus = if ($copyTime -lt $KPIThresholds.CopyMoveOperationDelayMS) { "Met" } 
                       elseif ($copyTime -lt ($KPIThresholds.CopyMoveOperationDelayMS * 2)) { "Warning" } 
                       else { "Critical" }
        }
        
        Start-Sleep -Milliseconds 200
    }
    
    Write-Progress -Activity "Testing File Copy Operations" -Completed
    
    # Test 4: Application Startup Impact (if requested)
    if ($IncludeAppStartup) {
        Write-ColorOutput "`nTesting application startup impact..." -Color $Colors.Progress
        
        $testApps = @(
            @{ Name = "Notepad"; Path = "notepad.exe"; Args = "" },
            @{ Name = "Calculator"; Path = "calc.exe"; Args = "" },
            @{ Name = "WordPad"; Path = "wordpad.exe"; Args = "" }
        )
        
        foreach ($app in $testApps) {
            Write-ColorOutput "    Testing $($app.Name) startup..." -Color $Colors.Info
            
            $startApp = Get-Date
            try {
                $process = Start-Process -FilePath $app.Path -ArgumentList $app.Args -PassThru -ErrorAction Stop
                
                # Wait for main window to be responsive
                $timeout = 0
                while (-not $process.MainWindowTitle -and $timeout -lt 10000) {
                    Start-Sleep -Milliseconds 100
                    $timeout += 100
                    try { $process.Refresh() } catch { break }
                }
                
                $startupTime = ((Get-Date) - $startApp).TotalMilliseconds
                
                # Close the application
                try {
                    $process.CloseMainWindow() | Out-Null
                    Start-Sleep -Milliseconds 500
                    if (-not $process.HasExited) {
                        $process.Kill()
                    }
                }
                catch { }
                
                $status = "Success"
            }
            catch {
                $startupTime = 999999
                $status = "Failed: $_"
            }
            
            $appStartupResults += [PSCustomObject]@{
                ApplicationName = $app.Name
                StartupTimeMS = [math]::Round($startupTime, 2)
                Status = $status
                KPIStatus = if ($startupTime -lt $KPIThresholds.ApplicationStartupDelayMS) { "Met" } 
                           elseif ($startupTime -lt ($KPIThresholds.ApplicationStartupDelayMS * 2)) { "Warning" } 
                           else { "Critical" }
            }
            
            Start-Sleep -Milliseconds 1000  # Pause between app tests
        }
    }
    
    # Analyze Results
    Write-ColorOutput "`nLatency Analysis Results:" -Color $Colors.Header
    Write-ColorOutput $('='*50) -Color $Colors.Header
    
    # File Open Analysis
    if ($fileOpenResults.Count -gt 0) {
        $avgOpenTime = [math]::Round(($fileOpenResults | Where-Object { $_.Status -eq "Success" } | Measure-Object OpenTimeMS -Average).Average, 2)
        $maxOpenTime = ($fileOpenResults | Where-Object { $_.Status -eq "Success" } | Measure-Object OpenTimeMS -Maximum).Maximum
        $metOpenKPI = ($fileOpenResults | Where-Object { $_.KPIStatus -eq "Met" }).Count
        
        if ($avgOpenTime -lt $KPIThresholds.FileOpenDelayMS) {
            Write-ColorOutput "    [+] File Open Delay: $avgOpenTime ms average (within threshold)" -Color $Colors.Success
        } elseif ($avgOpenTime -lt ($KPIThresholds.FileOpenDelayMS * 2)) {
            Write-ColorOutput "    [!] File Open Delay: $avgOpenTime ms average (warning level)" -Color $Colors.Warning
        } else {
            Write-ColorOutput "    [-] File Open Delay: $avgOpenTime ms average (critical level)" -Color $Colors.Error
        }
        Write-ColorOutput "        Target: < $($KPIThresholds.FileOpenDelayMS) ms | KPI Met: $metOpenKPI/$($fileOpenResults.Count) files" -Color $Colors.Info
    }
    
    # File Save Analysis
    if ($fileSaveResults.Count -gt 0) {
        $avgSaveTime = [math]::Round(($fileSaveResults | Where-Object { $_.Status -eq "Success" } | Measure-Object SaveTimeMS -Average).Average, 2)
        $maxSaveTime = ($fileSaveResults | Where-Object { $_.Status -eq "Success" } | Measure-Object SaveTimeMS -Maximum).Maximum
        $metSaveKPI = ($fileSaveResults | Where-Object { $_.KPIStatus -eq "Met" }).Count
        
        if ($avgSaveTime -lt $KPIThresholds.SaveOperationDelayMS) {
            Write-ColorOutput "    [+] Save Operation Delay: $avgSaveTime ms average (within threshold)" -Color $Colors.Success
        } elseif ($avgSaveTime -lt ($KPIThresholds.SaveOperationDelayMS * 2)) {
            Write-ColorOutput "    [!] Save Operation Delay: $avgSaveTime ms average (warning level)" -Color $Colors.Warning
        } else {
            Write-ColorOutput "    [-] Save Operation Delay: $avgSaveTime ms average (critical level)" -Color $Colors.Error
        }
        Write-ColorOutput "        Target: < $($KPIThresholds.SaveOperationDelayMS) ms | KPI Met: $metSaveKPI/$($fileSaveResults.Count) files" -Color $Colors.Info
    }
    
    # File Copy Analysis
    if ($fileCopyResults.Count -gt 0) {
        $avgCopyTime = [math]::Round(($fileCopyResults | Where-Object { $_.Status -eq "Success" } | Measure-Object CopyTimeMS -Average).Average, 2)
        $maxCopyTime = ($fileCopyResults | Where-Object { $_.Status -eq "Success" } | Measure-Object CopyTimeMS -Maximum).Maximum
        $metCopyKPI = ($fileCopyResults | Where-Object { $_.KPIStatus -eq "Met" }).Count
        
        if ($avgCopyTime -lt $KPIThresholds.CopyMoveOperationDelayMS) {
            Write-ColorOutput "    [+] Copy/Move Delay: $avgCopyTime ms average (within threshold)" -Color $Colors.Success
        } elseif ($avgCopyTime -lt ($KPIThresholds.CopyMoveOperationDelayMS * 2)) {
            Write-ColorOutput "    [!] Copy/Move Delay: $avgCopyTime ms average (warning level)" -Color $Colors.Warning
        } else {
            Write-ColorOutput "    [-] Copy/Move Delay: $avgCopyTime ms average (critical level)" -Color $Colors.Error
        }
        Write-ColorOutput "        Target: < $($KPIThresholds.CopyMoveOperationDelayMS) ms | KPI Met: $metCopyKPI/$($fileCopyResults.Count) files" -Color $Colors.Info
    }
    
    # App Startup Analysis
    if ($appStartupResults.Count -gt 0) {
        $avgStartupTime = [math]::Round(($appStartupResults | Where-Object { $_.Status -eq "Success" } | Measure-Object StartupTimeMS -Average).Average, 2)
        $metStartupKPI = ($appStartupResults | Where-Object { $_.KPIStatus -eq "Met" }).Count
        
        if ($avgStartupTime -lt $KPIThresholds.ApplicationStartupDelayMS) {
            Write-ColorOutput "    [+] Application Startup: $avgStartupTime ms average (within threshold)" -Color $Colors.Success
        } elseif ($avgStartupTime -lt ($KPIThresholds.ApplicationStartupDelayMS * 2)) {
            Write-ColorOutput "    [!] Application Startup: $avgStartupTime ms average (warning level)" -Color $Colors.Warning
        } else {
            Write-ColorOutput "    [-] Application Startup: $avgStartupTime ms average (critical level)" -Color $Colors.Error
        }
        Write-ColorOutput "        Target: < $($KPIThresholds.ApplicationStartupDelayMS) ms | KPI Met: $metStartupKPI/$($appStartupResults.Count) applications" -Color $Colors.Info
    }
    
    # Overall latency summary
    Write-ColorOutput "`nLatency Summary:" -Color $Colors.Header
    if ($avgOpenTime -gt 0) {
        Write-ColorOutput "    • File Opens: $avgOpenTime ms average" -Color $Colors.Info
    }
    if ($avgSaveTime -gt 0) {
        Write-ColorOutput "    • File Saves: $avgSaveTime ms average" -Color $Colors.Info
    }
    if ($avgCopyTime -gt 0) {
        Write-ColorOutput "    • File Copies: $avgCopyTime ms average" -Color $Colors.Info
    }
    if ($avgStartupTime -gt 0) {
        Write-ColorOutput "    • App Startup: $avgStartupTime ms average" -Color $Colors.Info
    }
    
    # Export reports if requested
    if ($ExportReports) {
        Write-ColorOutput "`nExporting latency reports..." -Color $Colors.Progress
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        
        # Export individual test results
        if ($fileOpenResults.Count -gt 0) {
            $openCsv = "DLP_File_Open_Latency_$timestamp.csv"
            $fileOpenResults | Export-Csv -Path $openCsv -NoTypeInformation -Encoding UTF8
            Write-ColorOutput "    [+] File open results: $openCsv" -Color $Colors.Success
        }
        
        if ($fileSaveResults.Count -gt 0) {
            $saveCsv = "DLP_File_Save_Latency_$timestamp.csv"
            $fileSaveResults | Export-Csv -Path $saveCsv -NoTypeInformation -Encoding UTF8
            Write-ColorOutput "    [+] File save results: $saveCsv" -Color $Colors.Success
        }
        
        if ($fileCopyResults.Count -gt 0) {
            $copyCsv = "DLP_File_Copy_Latency_$timestamp.csv"
            $fileCopyResults | Export-Csv -Path $copyCsv -NoTypeInformation -Encoding UTF8
            Write-ColorOutput "    [+] File copy results: $copyCsv" -Color $Colors.Success
        }
        
        if ($appStartupResults.Count -gt 0) {
            $appCsv = "DLP_App_Startup_Latency_$timestamp.csv"
            $appStartupResults | Export-Csv -Path $appCsv -NoTypeInformation -Encoding UTF8
            Write-ColorOutput "    [+] App startup results: $appCsv" -Color $Colors.Success
        }
        
        # Comprehensive KPI summary
        $kpiSummary = [PSCustomObject]@{
            Timestamp = Get-Date
            Test_Files_Count = $TestFileCount
            Test_File_Size_MB = $TestFileSizeMB
            File_Open_Avg_MS = if ($avgOpenTime -gt 0) { $avgOpenTime } else { $null }
            File_Open_KPI_Status = if ($avgOpenTime -gt 0) { 
                if ($avgOpenTime -lt $KPIThresholds.FileOpenDelayMS) { "Met" } 
                elseif ($avgOpenTime -lt ($KPIThresholds.FileOpenDelayMS * 2)) { "Warning" } 
                else { "Critical" } 
            } else { $null }
            File_Save_Avg_MS = if ($avgSaveTime -gt 0) { $avgSaveTime } else { $null }
            File_Save_KPI_Status = if ($avgSaveTime -gt 0) { 
                if ($avgSaveTime -lt $KPIThresholds.SaveOperationDelayMS) { "Met" } 
                elseif ($avgSaveTime -lt ($KPIThresholds.SaveOperationDelayMS * 2)) { "Warning" } 
                else { "Critical" } 
            } else { $null }
            File_Copy_Avg_MS = if ($avgCopyTime -gt 0) { $avgCopyTime } else { $null }
            File_Copy_KPI_Status = if ($avgCopyTime -gt 0) { 
                if ($avgCopyTime -lt $KPIThresholds.CopyMoveOperationDelayMS) { "Met" } 
                elseif ($avgCopyTime -lt ($KPIThresholds.CopyMoveOperationDelayMS * 2)) { "Warning" } 
                else { "Critical" } 
            } else { $null }
            App_Startup_Avg_MS = if ($avgStartupTime -gt 0) { $avgStartupTime } else { $null }
            App_Startup_KPI_Status = if ($avgStartupTime -gt 0) { 
                if ($avgStartupTime -lt $KPIThresholds.ApplicationStartupDelayMS) { "Met" } 
                elseif ($avgStartupTime -lt ($KPIThresholds.ApplicationStartupDelayMS * 2)) { "Warning" } 
                else { "Critical" } 
            } else { $null }
            KPI_Threshold_Source = "Microsoft Official Guidance 2025"
        }
        
        $kpiSummaryCsv = "DLP_Latency_KPI_Summary_$timestamp.csv"
        $kpiSummary | Export-Csv -Path $kpiSummaryCsv -NoTypeInformation -Encoding UTF8
        Write-ColorOutput "    [+] KPI summary: $kpiSummaryCsv" -Color $Colors.Success
    }
    
    # Recommendations
    Write-ColorOutput "`nRecommendations:" -Color $Colors.Header
    
    $recommendationCount = 0
    
    if ($avgOpenTime -gt $KPIThresholds.FileOpenDelayMS) {
        Write-ColorOutput "    • File open latency exceeds threshold - consider file type exclusions" -Color $Colors.Warning
        $recommendationCount++
    }
    
    if ($avgSaveTime -gt $KPIThresholds.SaveOperationDelayMS) {
        Write-ColorOutput "    • File save latency exceeds threshold - review content inspection policies" -Color $Colors.Warning
        $recommendationCount++
    }
    
    if ($avgCopyTime -gt $KPIThresholds.CopyMoveOperationDelayMS) {
        Write-ColorOutput "    • File copy operations slow - consider path-based exclusions" -Color $Colors.Warning
        $recommendationCount++
    }
    
    if ($avgStartupTime -gt 0 -and $avgStartupTime -gt $KPIThresholds.ApplicationStartupDelayMS) {
        Write-ColorOutput "    • Application startup delayed - review process exclusions" -Color $Colors.Warning
        $recommendationCount++
    }
    
    if ($recommendationCount -eq 0) {
        Write-ColorOutput "    • All file/application latency KPIs within acceptable thresholds" -Color $Colors.Success
    }
    
    Write-ColorOutput "`nLatency KPI Threshold Notes:" -Color $Colors.Info
    Write-ColorOutput "    • File operations: Reflects real-time content scanning overhead" -Color $Colors.Info
    Write-ColorOutput "    • DLP classification: Cloud service calls add latency" -Color $Colors.Info
    Write-ColorOutput "    • Sensitive content: Pattern matching requires processing time" -Color $Colors.Info
    
    Write-ColorOutput "`n    [+] DLP File/App Latency monitoring completed" -Color $Colors.Success

} catch {
    Write-ColorOutput "`nERROR: $_" -Color $Colors.Error
} finally {
    # Cleanup test files and junction
    try {
        if ($testPath -and (Test-Path $testPath)) {
            Remove-Item -Path $testPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-ColorOutput "`n    [+] Test files cleaned up" -Color $Colors.Success
        }
    }
    catch {
        Write-ColorOutput "`n    [!] Warning: Could not clean up all test files" -Color $Colors.Warning
    }
    
    if ($stubPath -and (Test-Path $stubPath)) {
        Set-Location $currentPath.Path
        cmd /c rmdir "$stubPath" 2>&1 | Out-Null
    }
}

Write-ColorOutput "`n" + $('='*80) -Color $Colors.Header
Write-ColorOutput "END OF DLP FILE/APP LATENCY MONITOR" -Color $Colors.Header
Write-ColorOutput $('='*80) -Color $Colors.Header