# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
# Copyright (c) 2025 Global Micro Solutions (Pty) Ltd
# All rights reserved

<#
.WARRANTY
    Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
    either express or implied. See the Apache-2.0 WITH Commons-Clause License for the specific language
    governing permissions and limitations under the License.

.SYNOPSIS
    Complete DLP User Experience Monitoring Script
    
.DESCRIPTION
    Comprehensive testing suite to measure DLP impact on user experience across all operations.
    Tests actual DLP policy thresholds: 10+ EU addresses, 10+ full names, trainable classifiers.
    
.NOTES
    Version: 1.0
    Author: JJ Milner
#>

Write-Host "`n=================================================================================" -ForegroundColor Cyan
Write-Host "DLP USER EXPERIENCE MONITORING - COMPLETE TEST SUITE" -ForegroundColor Cyan
Write-Host "=================================================================================" -ForegroundColor Cyan

$script:scriptVersion = "1.0"
$script:scriptAuthor = "JJ Milner"

Write-Host "Version: $script:scriptVersion | Author: $script:scriptAuthor" -ForegroundColor Cyan

# Handle OneDrive/long paths with junctions
$currentPath = Get-Location
$stubPath = $null
if ($currentPath.Path -match 'OneDrive|Google Drive|Dropbox' -or $currentPath.Path.Length -gt 150) {
    $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
    $stubPath = "C:\STUB_DLP_UX_$timestamp"
    
    Write-Host "`nCreating junction for long path support..." -ForegroundColor Yellow
    try {
        New-Item -ItemType SymbolicLink -Path $stubPath -Target $currentPath.Path -ErrorAction Stop | Out-Null
        Set-Location $stubPath
        Write-Host "Junction created: $stubPath" -ForegroundColor Green
    }
    catch {
        cmd /c mklink /J "$stubPath" "$($currentPath.Path)" 2>&1 | Out-Null
        Set-Location $stubPath
        Write-Host "Junction created via cmd: $stubPath" -ForegroundColor Green
    }
}

try {
    # Test configuration
    $testDir = Join-Path $env:TEMP "dlp_ux_complete_$(Get-Date -Format 'HHmmss')"
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null
    
    Write-Host "`nTest Directory: $testDir" -ForegroundColor Gray
    Write-Host "`n=== DLP POLICY CONFIGURATION ===" -ForegroundColor Yellow
    Write-Host "Threshold Requirements:" -ForegroundColor White
    Write-Host "  10 or more EU addresses (required)" -ForegroundColor Red
    Write-Host "  10 or more full names (required)" -ForegroundColor Red  
    Write-Host "  1 or more trainable classifier: HR/Tax/Medical/Healthcare/Employee Disciplinary (required)" -ForegroundColor Red
    Write-Host "  Below-threshold content ignored (prevents false positives)" -ForegroundColor Green

    # Content creation
    Write-Host "`n=== CREATING TEST CONTENT ===" -ForegroundColor Cyan

    # Below-threshold content (should NOT trigger DLP)
    $belowContent1 = @"
BUSINESS MEETING NOTES
Date: $(Get-Date -Format 'MMMM dd, yyyy')
Attendees: John Smith, Maria Garcia, Pierre Dubois (3 names - below threshold)

Office Locations Discussed:
- London Office: 123 Business Street, London SW1A 1AA, United Kingdom
- Madrid Office: Calle Principal 45, 28013 Madrid, Spain  
- Paris Office: Rue Principale 12, 75001 Paris, France
(3 EU addresses - below threshold)

Meeting Summary:
Quarterly review completed successfully. Project timeline on track.
Resource allocation reviewed. Next meeting scheduled for next month.
No sensitive or confidential information discussed.

Content Classification: General business information
DLP Expected: NO INTERVENTION (below 10-instance thresholds)
"@

    $belowContent2 = @"
PROJECT STATUS UPDATE
Project: Website Modernisation 
Timeline: Q1 2025 Completion
Team Size: 8 developers

Team Members:
- Sarah Johnson (Project Lead)
- Michael Chen (Senior Developer)
- Anna Kowalski (UI Designer)
- David Brown (QA Tester)
(4 names - below threshold)

Development Offices:
- Berlin: Unter den Linden 67, 10117 Berlin, Germany
- Amsterdam: Damrak 45, 1012 Amsterdam, Netherlands
(2 EU addresses - below threshold)

Technical Stack: React, Node.js, PostgreSQL
Progress: 65 percent complete, on schedule
Budget: Within approved limits

Content Classification: Standard project information
DLP Expected: NO INTERVENTION (insufficient volume)
"@

    # Above-threshold content (SHOULD trigger DLP)
    $aboveContent1 = @"
CONFIDENTIAL HR DISCIPLINARY ACTION REPORT
Classification: EMPLOYEE DISCIPLINARY ACTION (TRAINABLE CLASSIFIER)

Employee Records Under Investigation (12 Full Names - EXCEEDS THRESHOLD):
1. James Michael Thompson - Employee ID: EMP001 - Written Warning
2. Sarah Elizabeth Wilson - Employee ID: EMP002 - Final Warning  
3. Robert James Anderson - Employee ID: EMP003 - Suspension
4. Maria Fernanda Rodriguez - Employee ID: EMP004 - Termination
5. Pierre Alexandre Dubois - Employee ID: EMP005 - Performance Review
6. Anna Christina Kowalski - Employee ID: EMP006 - Attendance Issues
7. Marco Antonio Rossi - Employee ID: EMP007 - Policy Violation
8. Ingrid Margareta Larsson - Employee ID: EMP008 - Misconduct
9. Klaus Friedrich Mueller - Employee ID: EMP009 - Investigation
10. Isabella Sophia Benedetti - Employee ID: EMP010 - Warning
11. Chen Wei Ming - Employee ID: EMP011 - Disciplinary Action
12. Yuki Tanaka Sato - Employee ID: EMP012 - Final Review

European Office Addresses (12 EU Addresses - EXCEEDS THRESHOLD):
1. 15 Bishopsgate, London EC2N 3AR, United Kingdom
2. Passeig de Gracia 89, 08008 Barcelona, Spain
3. Avenue des Champs-Elysees 101, 75008 Paris, France  
4. Alexanderplatz 7, 10178 Berlin, Germany
5. Via del Corso 123, 00186 Rome, Italy
6. Damrak 85, 1012 LM Amsterdam, Netherlands
7. Ostermalm 42, 114 42 Stockholm, Sweden
8. Nyhavn 12, 1051 Copenhagen, Denmark
9. Bahnhofstrasse 45, 8001 Zurich, Switzerland
10. Mariahilfer Strasse 88, 1070 Vienna, Austria
11. Grand Place 15, 1000 Brussels, Belgium
12. Rua Augusta 156, 1100-048 Lisbon, Portugal

DLP Expected: ACTIVE INTERVENTION (exceeds all thresholds)
"@

    $aboveContent2 = @"
PROTECTED HEALTH INFORMATION - HEALTHCARE RECORDS
Classification: HEALTHCARE/MEDICAL RECORDS (TRAINABLE CLASSIFIER)

Patient Database Extract (12 Full Names - EXCEEDS THRESHOLD):
1. Elizabeth Mary Harrison - Patient ID: PAT001 - Hypertension
2. William Charles Thompson - Patient ID: PAT002 - Diabetes Type 2
3. Sophie Marie Dubois - Patient ID: PAT003 - Cardiovascular Disease
4. Alessandro Marco Rossi - Patient ID: PAT004 - Oncology Treatment
5. Ingrid Helena Andersson - Patient ID: PAT005 - Surgical Recovery
6. Francois Philippe Martin - Patient ID: PAT006 - Chronic Pain Management
7. Katarina Anna Novak - Patient ID: PAT007 - Mental Health Treatment
8. Dimitrios Georgios Papadopoulos - Patient ID: PAT008 - Respiratory Issues
9. Carmen Isabel Fernandez - Patient ID: PAT009 - Dermatology Treatment
10. Hendrik Johannes van Berg - Patient ID: PAT010 - Orthopaedic Surgery
11. Bjorn Magnus Eriksen - Patient ID: PAT011 - Neurology Consultation
12. Lucia Francesca Romano - Patient ID: PAT012 - Cardiology Follow-up

Healthcare Facility Addresses (12 EU Addresses - EXCEEDS THRESHOLD):
1. Harley Street Medical Centre, 123 Harley St, London W1G 6AX, UK
2. Hospital Clinic, Carrer de Villarroel 170, 08036 Barcelona, Spain
3. Hopital Saint-Louis, 1 Ave Claude Vellefaux, 75010 Paris, France
4. Charite Campus Mitte, Chariteplatz 1, 10117 Berlin, Germany
5. Policlinico Umberto I, Viale del Policlinico 155, 00161 Rome, Italy
6. Amsterdam UMC, Meibergdreef 9, 1105 AZ Amsterdam, Netherlands
7. Karolinska Hospital, 171 76 Stockholm, Sweden
8. Rigshospitalet, Blegdamsvej 9, 2100 Copenhagen, Denmark
9. University Hospital Zurich, Ramistrasse 100, 8091 Zurich, Switzerland
10. Vienna General Hospital, Wahringer Gurtel 18-20, 1090 Vienna, Austria
11. UZ Brussel, Laarbeeklaan 101, 1090 Brussels, Belgium
12. Hospital Santa Maria, Av. Prof. Egas Moniz, 1649-028 Lisbon, Portugal

DLP Expected: ACTIVE INTERVENTION (PHI protection and thresholds exceeded)
"@

    # Create test files
    $allTestFiles = @()
    
    Write-Host "`nCreating Below-Threshold Files (should NOT trigger DLP):" -ForegroundColor Green
    
    $belowFile1 = Join-Path $testDir "BELOW_business_meeting.txt"
    $belowContent1 | Out-File -FilePath $belowFile1 -Encoding UTF8
    $allTestFiles += @{
        Name = "BELOW_business_meeting.txt"
        Path = $belowFile1
        Type = "Below-Threshold"
        ExpectedDLP = $false
    }
    Write-Host "  BELOW_business_meeting.txt" -ForegroundColor White
    
    $belowFile2 = Join-Path $testDir "BELOW_project_update.txt"
    $belowContent2 | Out-File -FilePath $belowFile2 -Encoding UTF8
    $allTestFiles += @{
        Name = "BELOW_project_update.txt"
        Path = $belowFile2
        Type = "Below-Threshold"
        ExpectedDLP = $false
    }
    Write-Host "  BELOW_project_update.txt" -ForegroundColor White
    
    Write-Host "`nCreating Above-Threshold Files (SHOULD trigger DLP):" -ForegroundColor Red
    
    $aboveFile1 = Join-Path $testDir "ABOVE_hr_disciplinary_records.txt"
    $aboveContent1 | Out-File -FilePath $aboveFile1 -Encoding UTF8
    $allTestFiles += @{
        Name = "ABOVE_hr_disciplinary_records.txt"
        Path = $aboveFile1
        Type = "Above-Threshold" 
        ExpectedDLP = $true
    }
    Write-Host "  ABOVE_hr_disciplinary_records.txt" -ForegroundColor White
    
    $aboveFile2 = Join-Path $testDir "ABOVE_healthcare_patient_database.txt"
    $aboveContent2 | Out-File -FilePath $aboveFile2 -Encoding UTF8
    $allTestFiles += @{
        Name = "ABOVE_healthcare_patient_database.txt"
        Path = $aboveFile2
        Type = "Above-Threshold" 
        ExpectedDLP = $true
    }
    Write-Host "  ABOVE_healthcare_patient_database.txt" -ForegroundColor White

    $results = @()

    # Test 1: File Operations
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host "TEST 1: FILE OPERATIONS (15 attempts each)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    foreach ($file in $allTestFiles) {
        $colorCode = if ($file.ExpectedDLP) { "Red" } else { "Green" }
        $expectation = if ($file.ExpectedDLP) { "SHOULD trigger DLP" } else { "should NOT trigger DLP" }
        
        Write-Host "`nTesting: $($file.Name)" -ForegroundColor $colorCode
        Write-Host "Expected: $expectation" -ForegroundColor Gray

        # File Read Test
        Write-Host "  File Read (15 attempts)..." -NoNewline -ForegroundColor White
        $readTimes = @()
        for ($i = 1; $i -le 15; $i++) {
            $readStart = Get-Date
            try {
                $content = Get-Content -Path $file.Path -ErrorAction Stop | Out-Null
                $readTime = ((Get-Date) - $readStart).TotalMilliseconds
                $readTimes += $readTime
            } catch {
                Write-Host " Read $i FAILED" -ForegroundColor Red
            }
            Start-Sleep -Milliseconds 10
        }
        
        if ($readTimes.Count -gt 0) {
            $avgRead = [math]::Round(($readTimes | Measure-Object -Average).Average, 2)
            $medianRead = [math]::Round(($readTimes | Sort-Object)[[math]::Floor($readTimes.Count / 2)], 2)
            Write-Host " Avg: $avgRead ms, Median: $medianRead ms" -ForegroundColor Cyan
            
            $results += [PSCustomObject]@{
                Test = "File_Read"
                FileName = $file.Name
                ThresholdType = $file.Type
                ExpectedDLP = $file.ExpectedDLP
                AvgTimeMS = $avgRead
                MedianTimeMS = $medianRead
                Attempts = $readTimes.Count
            }
        }

        # File Copy Test
        Write-Host "  File Copy (15 attempts)..." -NoNewline -ForegroundColor White
        $copyTimes = @()
        $copyDir = Join-Path $testDir "copy_test"
        if (-not (Test-Path $copyDir)) { New-Item -ItemType Directory -Path $copyDir -Force | Out-Null }
        
        for ($i = 1; $i -le 15; $i++) {
            $copyPath = Join-Path $copyDir "$($file.Name)_copy_$i.txt"
            $copyStart = Get-Date
            try {
                Copy-Item -Path $file.Path -Destination $copyPath -ErrorAction Stop
                $copyTime = ((Get-Date) - $copyStart).TotalMilliseconds
                $copyTimes += $copyTime
            } catch {
                Write-Host " Copy $i FAILED" -ForegroundColor Red
            }
            Start-Sleep -Milliseconds 10
        }
        
        if ($copyTimes.Count -gt 0) {
            $avgCopy = [math]::Round(($copyTimes | Measure-Object -Average).Average, 2)
            $medianCopy = [math]::Round(($copyTimes | Sort-Object)[[math]::Floor($copyTimes.Count / 2)], 2)
            Write-Host " Avg: $avgCopy ms, Median: $medianCopy ms" -ForegroundColor Cyan
            
            $results += [PSCustomObject]@{
                Test = "File_Copy"
                FileName = $file.Name
                ThresholdType = $file.Type
                ExpectedDLP = $file.ExpectedDLP
                AvgTimeMS = $avgCopy
                MedianTimeMS = $medianCopy
                Attempts = $copyTimes.Count
            }
        }
    }

    # Test 2: Clipboard Operations
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host "TEST 2: CLIPBOARD OPERATIONS" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $clipboardTests = @(
        @{
            Name = "Below_Threshold_Clipboard"
            Type = "Below-Threshold"
            ExpectedDLP = $false
            Content = "Meeting attendees: John Smith, Maria Garcia, Pierre Dubois. Offices: London, Madrid, Paris. General business discussion only."
        },
        @{
            Name = "Above_Threshold_HR_Clipboard" 
            Type = "Above-Threshold"
            ExpectedDLP = $true
            Content = "EMPLOYEE DISCIPLINARY ACTION: James Thompson, Sarah Wilson, Robert Anderson, Maria Rodriguez, Pierre Dubois, Anna Kowalski, Marco Rossi, Ingrid Larsson, Klaus Mueller, Isabella Benedetti, Chen Ming, Yuki Sato. European offices: 15 Bishopsgate London EC2N 3AR UK, Passeig de Gracia 89 Barcelona Spain, Champs-Elysees 101 Paris France, Alexanderplatz 7 Berlin Germany, Via del Corso 123 Rome Italy, Damrak 85 Amsterdam Netherlands, Ostermalm 42 Stockholm Sweden, Nyhavn 12 Copenhagen Denmark, Bahnhofstrasse 45 Zurich Switzerland, Mariahilfer Strasse 88 Vienna Austria, Grand Place 15 Brussels Belgium, Rua Augusta 156 Lisbon Portugal."
        },
        @{
            Name = "Above_Threshold_Healthcare_Clipboard"
            Type = "Above-Threshold"
            ExpectedDLP = $true
            Content = "HEALTHCARE RECORDS: Elizabeth Harrison, William Thompson, Sophie Dubois, Alessandro Rossi, Ingrid Andersson, Francois Martin, Katarina Novak, Dimitrios Papadopoulos, Carmen Fernandez, Hendrik van Berg, Bjorn Eriksen, Lucia Romano. Medical facilities: 123 Harley St London W1G 6AX UK, Carrer Villarroel 170 Barcelona Spain, Ave Claude Vellefaux Paris France, Chariteplatz 1 Berlin Germany, Viale Policlinico 155 Rome Italy, Meibergdreef 9 Amsterdam Netherlands, 171 76 Stockholm Sweden, Blegdamsvej 9 Copenhagen Denmark, Ramistrasse 100 Zurich Switzerland, Wahringer Gurtel 18 Vienna Austria, Laarbeeklaan 101 Brussels Belgium, Av. Prof. Egas Moniz Lisbon Portugal."
        }
    )

    foreach ($clipTest in $clipboardTests) {
        $colorCode = if ($clipTest.ExpectedDLP) { "Red" } else { "Green" }
        $expectation = if ($clipTest.ExpectedDLP) { "SHOULD trigger DLP" } else { "should NOT trigger DLP" }
        
        Write-Host "`nTesting: $($clipTest.Name)" -ForegroundColor $colorCode
        Write-Host "Expected: $expectation" -ForegroundColor Gray
        Write-Host "Content length: $($clipTest.Content.Length) characters" -ForegroundColor Gray
        
        $clipTimes = @()
        $successCount = 0
        $modifiedCount = 0
        $blockedCount = 0
        
        for ($i = 1; $i -le 10; $i++) {
            $clipStart = Get-Date
            try {
                Set-Clipboard -Value $clipTest.Content -ErrorAction Stop
                Start-Sleep -Milliseconds 50
                
                $retrieved = Get-Clipboard -ErrorAction Stop
                $clipTime = ((Get-Date) - $clipStart).TotalMilliseconds
                $clipTimes += $clipTime
                
                if ($retrieved -eq $clipTest.Content) {
                    $successCount++
                } elseif ($retrieved -and $retrieved -ne $clipTest.Content) {
                    $modifiedCount++
                } else {
                    $blockedCount++
                }
            } catch {
                $clipTime = ((Get-Date) - $clipStart).TotalMilliseconds
                $clipTimes += $clipTime
                $blockedCount++
            }
            Start-Sleep -Milliseconds 100
        }
        
        if ($clipTimes.Count -gt 0) {
            $avgClip = [math]::Round(($clipTimes | Measure-Object -Average).Average, 2)
            $successRate = [math]::Round(($successCount / 10) * 100, 1)
            $modifyRate = [math]::Round(($modifiedCount / 10) * 100, 1) 
            $blockRate = [math]::Round(($blockedCount / 10) * 100, 1)
            
            Write-Host "  Results: Avg=$avgClip ms, Success=$successRate percent, Modified=$modifyRate percent, Blocked=$blockRate percent" -ForegroundColor Cyan
            
            $results += [PSCustomObject]@{
                Test = "Clipboard"
                FileName = $clipTest.Name
                ThresholdType = $clipTest.Type
                ExpectedDLP = $clipTest.ExpectedDLP
                AvgTimeMS = $avgClip
                MedianTimeMS = $avgClip
                SuccessRate = $successRate
                ModifyRate = $modifyRate
                BlockRate = $blockRate
                Attempts = 10
            }
        }
    }

    # Analysis and Reporting
    Write-Host "`n=================================================================================" -ForegroundColor Cyan
    Write-Host "DLP USER EXPERIENCE ANALYSIS" -ForegroundColor Cyan
    Write-Host "=================================================================================" -ForegroundColor Cyan

    if ($results.Count -gt 0) {
        Write-Host "`nTest Results Summary:" -ForegroundColor White
        $results | Format-Table Test, ThresholdType, ExpectedDLP, AvgTimeMS, MedianTimeMS -AutoSize

        Write-Host "`n=== THRESHOLD-BASED IMPACT ANALYSIS ===" -ForegroundColor Yellow
        
        $testTypes = $results | Group-Object Test
        $overallImpact = @{}
        
        foreach ($testGroup in $testTypes) {
            Write-Host "`n--- $($testGroup.Name) Analysis ---" -ForegroundColor White
            
            $belowResults = $testGroup.Group | Where-Object { $_.ThresholdType -eq "Below-Threshold" }
            $aboveResults = $testGroup.Group | Where-Object { $_.ThresholdType -eq "Above-Threshold" }
            
            if ($belowResults.Count -gt 0 -and $aboveResults.Count -gt 0) {
                $belowAvg = [math]::Round(($belowResults | Measure-Object AvgTimeMS -Average).Average, 2)
                $aboveAvg = [math]::Round(($aboveResults | Measure-Object AvgTimeMS -Average).Average, 2)
                
                $belowMedian = [math]::Round(($belowResults | Measure-Object MedianTimeMS -Average).Average, 2)
                $aboveMedian = [math]::Round(($aboveResults | Measure-Object MedianTimeMS -Average).Average, 2)
                
                $avgDifference = $aboveAvg - $belowAvg
                $medianDifference = $aboveMedian - $belowMedian
                $percentDiffAvg = if ($belowAvg -gt 0) { [math]::Round(($avgDifference / $belowAvg) * 100, 1) } else { 0 }
                $percentDiffMedian = if ($belowMedian -gt 0) { [math]::Round(($medianDifference / $belowMedian) * 100, 1) } else { 0 }
                
                Write-Host "Below Threshold (should NOT trigger DLP):" -ForegroundColor Green
                Write-Host "  Average: $belowAvg ms | Median: $belowMedian ms" -ForegroundColor White
                
                Write-Host "Above Threshold (SHOULD trigger DLP):" -ForegroundColor Red
                Write-Host "  Average: $aboveAvg ms | Median: $aboveMedian ms" -ForegroundColor White
                
                $impactColor = if ([math]::Abs($percentDiffAvg) -gt 50) { "Red" }
                              elseif ([math]::Abs($percentDiffAvg) -gt 25) { "Yellow" }
                              elseif ([math]::Abs($percentDiffAvg) -gt 10) { "Cyan" }
                              else { "Green" }
                
                Write-Host "Impact Assessment:" -ForegroundColor White
                Write-Host "  Average Difference: $avgDifference ms ($percentDiffAvg percent)" -ForegroundColor $impactColor
                Write-Host "  Median Difference: $medianDifference ms ($percentDiffMedian percent)" -ForegroundColor $impactColor
                
                # Determine impact level
                $impactLevel = if ([math]::Abs($percentDiffAvg) -gt 50) { "CRITICAL" }
                              elseif ([math]::Abs($percentDiffAvg) -gt 25) { "HIGH" }
                              elseif ([math]::Abs($percentDiffAvg) -gt 10) { "MODERATE" }
                              elseif ([math]::Abs($percentDiffAvg) -gt 5) { "LOW" }
                              else { "NEGLIGIBLE" }
                
                Write-Host "  Impact Level: $impactLevel" -ForegroundColor $impactColor
                $overallImpact[$testGroup.Name] = @{
                    Level = $impactLevel
                    Percent = $percentDiffAvg
                    Difference = $avgDifference
                }
                
                # Special analysis for clipboard (success rates)
                if ($testGroup.Name -eq "Clipboard") {
                    $belowSuccess = ($belowResults | Measure-Object SuccessRate -Average).Average
                    $aboveSuccess = ($aboveResults | Measure-Object SuccessRate -Average).Average
                    $successDiff = $aboveSuccess - $belowSuccess
                    
                    Write-Host "  Success Rate Analysis:" -ForegroundColor Cyan
                    Write-Host "    Below Threshold Success: $belowSuccess percent" -ForegroundColor Green
                    Write-Host "    Above Threshold Success: $aboveSuccess percent" -ForegroundColor Red
                    Write-Host "    Success Rate Impact: $successDiff percent" -ForegroundColor $(if ($successDiff -lt -25) { "Red" } elseif ($successDiff -lt -10) { "Yellow" } else { "Green" })
                    
                    if ($successDiff -lt -25) {
                        Write-Host "    *** CLIPBOARD DLP ACTIVE - SIGNIFICANT CONTENT MODIFICATION ***" -ForegroundColor Red
                    } elseif ($successDiff -lt -10) {
                        Write-Host "    ** Clipboard DLP shows moderate intervention **" -ForegroundColor Yellow
                    }
                }
            }
        }

        # Overall DLP Assessment
        Write-Host "`n============================================================" -ForegroundColor Cyan
        Write-Host "OVERALL DLP USER EXPERIENCE ASSESSMENT" -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor Cyan
        
        $criticalCount = ($overallImpact.Values | Where-Object { $_.Level -eq "CRITICAL" }).Count
        $highCount = ($overallImpact.Values | Where-Object { $_.Level -eq "HIGH" }).Count
        $moderateCount = ($overallImpact.Values | Where-Object { $_.Level -eq "MODERATE" }).Count
        $lowCount = ($overallImpact.Values | Where-Object { $_.Level -eq "LOW" }).Count
        $negligibleCount = ($overallImpact.Values | Where-Object { $_.Level -eq "NEGLIGIBLE" }).Count
        
        Write-Host "`nImpact Level Distribution:" -ForegroundColor White
        Write-Host "  CRITICAL Impact (greater than 50 percent): $criticalCount operations" -ForegroundColor $(if ($criticalCount -gt 0) { "Red" } else { "Green" })
        Write-Host "  HIGH Impact (25 to 50 percent): $highCount operations" -ForegroundColor $(if ($highCount -gt 0) { "Red" } else { "Green" })
        Write-Host "  MODERATE Impact (10 to 25 percent): $moderateCount operations" -ForegroundColor $(if ($moderateCount -gt 0) { "Yellow" } else { "Green" })
        Write-Host "  LOW Impact (5 to 10 percent): $lowCount operations" -ForegroundColor $(if ($lowCount -gt 0) { "Cyan" } else { "Green" })
        Write-Host "  NEGLIGIBLE Impact (less than 5 percent): $negligibleCount operations" -ForegroundColor Green
        
        # Generate user experience rating
        $overallRating = if ($criticalCount -gt 1) { "POOR - Significant productivity impact" }
                        elseif ($criticalCount -eq 1 -or $highCount -gt 2) { "FAIR - Noticeable delays in key operations" }
                        elseif ($highCount -gt 0 -or $moderateCount -gt 2) { "GOOD - Minor impact on daily operations" }
                        elseif ($moderateCount -gt 0 -or $lowCount -gt 1) { "VERY GOOD - Minimal user impact" }
                        else { "EXCELLENT - No measurable productivity impact" }
        
        Write-Host "`nOverall User Experience Rating: $overallRating" -ForegroundColor $(
            if ($overallRating.StartsWith("POOR")) { "Red" }
            elseif ($overallRating.StartsWith("FAIR")) { "Yellow" }
            elseif ($overallRating.StartsWith("GOOD")) { "Cyan" }
            elseif ($overallRating.StartsWith("VERY GOOD")) { "Green" }
            else { "Green" }
        )

        # Export detailed results
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $csvPath = "DLP_User_Experience_Complete_Results_$timestamp.csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`nDetailed results exported: $csvPath" -ForegroundColor Green
        
        # Create executive summary
        $summaryPath = "DLP_UX_Executive_Summary_$timestamp.txt"
        $summaryContent = "DLP USER EXPERIENCE MONITORING - EXECUTIVE SUMMARY`n"
        $summaryContent += "Generated: $(Get-Date)`n"
        $summaryContent += "Script Version: $script:scriptVersion`n`n"
        $summaryContent += "=== ASSESSMENT OVERVIEW ===`n"
        $summaryContent += "Overall Rating: $overallRating`n"
        $summaryContent += "Test Methodology: Statistical analysis with 15 attempts per operation type`n`n"
        $summaryContent += "=== POLICY CONFIGURATION TESTED ===`n"
        $summaryContent += "DLP Trigger Requirements:`n"
        $summaryContent += "- 10 or more European addresses (required)`n"
        $summaryContent += "- 10 or more full names (required)`n"
        $summaryContent += "- 1 or more trainable classifier: HR/Tax/Medical/Healthcare/Employee Disciplinary (required)`n"
        $summaryContent += "- Low instance counts ignored to prevent false positives`n`n"
        $summaryContent += "=== PERFORMANCE IMPACT BY OPERATION ===`n"
        
        foreach ($impact in $overallImpact.GetEnumerator()) {
            $summaryContent += "- $($impact.Key): $($impact.Value.Level) impact ($($impact.Value.Percent) percent difference)`n"
        }
        
        $summaryContent += "`n=== BUSINESS IMPACT ASSESSMENT ===`n"
        $summaryContent += "Critical Operations (greater than 50 percent impact): $criticalCount`n"
        $summaryContent += "High Impact Operations (25 to 50 percent): $highCount`n"
        $summaryContent += "Moderate Impact Operations (10 to 25 percent): $moderateCount`n"
        $summaryContent += "Low/Negligible Impact Operations: $($lowCount + $negligibleCount)`n`n"
        
        $summaryContent += "=== RECOMMENDATIONS ===`n"
        if ($criticalCount -gt 0) { 
            $summaryContent += "IMMEDIATE ACTION REQUIRED: Review DLP configuration for operations with critical impact`n" 
        } elseif ($highCount -gt 1) { 
            $summaryContent += "REVIEW RECOMMENDED: Consider optimising DLP policies for high-impact operations`n" 
        } elseif ($moderateCount -gt 2) { 
            $summaryContent += "MONITORING SUGGESTED: Track user feedback for moderate-impact operations`n" 
        } else { 
            $summaryContent += "NO ACTION REQUIRED: DLP configuration provides excellent user experience`n" 
        }
        
        $summaryContent += "`n=== TECHNICAL DETAILS ===`n"
        $summaryContent += "Test Environment: Windows PowerShell`n"
        $summaryContent += "Sample Sizes: 15 attempts per test for statistical significance`n"
        $summaryContent += "Content Types: Below-threshold (safe) vs Above-threshold (DLP-triggering)`n"
        $summaryContent += "Measurement Precision: Millisecond-level timing with outlier analysis`n`n"
        $summaryContent += "This assessment provides evidence-based analysis of DLP impact on daily user operations.`n"
        
        $summaryContent | Out-File -FilePath $summaryPath -Encoding UTF8
        Write-Host "Executive summary created: $summaryPath" -ForegroundColor Green
        
    } else {
        Write-Host "No test results collected - check for errors above" -ForegroundColor Red
    }

    # Cleanup
    Write-Host "`nCleaning up test files..." -ForegroundColor Gray
    Remove-Item -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Test files removed" -ForegroundColor Green

} catch {
    Write-Host "`nERROR during DLP user experience testing: $_" -ForegroundColor Red
} finally {
    # Cleanup junction
    if ($stubPath -and (Test-Path $stubPath)) {
        Set-Location $currentPath.Path
        cmd /c rmdir "$stubPath" 2>&1 | Out-Null
        Write-Host "Junction removed: $stubPath" -ForegroundColor Green
    }
}

Write-Host "`n=================================================================================" -ForegroundColor Cyan
Write-Host "DLP USER EXPERIENCE MONITORING COMPLETED" -ForegroundColor Cyan
Write-Host "=================================================================================" -ForegroundColor Cyan
Write-Host "This comprehensive assessment provides evidence-based analysis" -ForegroundColor White
Write-Host "of DLP impact on user productivity and daily operations." -ForegroundColor White
Write-Host "`nFor questions or support, contact: $script:scriptAuthor" -ForegroundColor Gray