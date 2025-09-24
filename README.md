# Microsoft Purview DLP Performance Monitoring Suite

Comprehensive PowerShell-based monitoring suite for Microsoft Purview Data Loss Prevention (DLP) and Microsoft Defender for Endpoint, providing enterprise-grade performance analysis, KPI tracking, and operational health assessment.

![License](https://img.shields.io/badge/License-Apache%202.0%20WITH%20Commons--Clause-blue.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)

## 🚀 Overview

This suite provides comprehensive monitoring capabilities for Microsoft Purview DLP deployments, focusing on:

- **Operational Health**: Event log analysis with intelligent DLP vs. system error classification
- **Performance Impact**: Real-time CPU, memory, and disk I/O monitoring of DLP processes
- **User Experience**: File operation latency and application startup impact measurement
- **Policy Effectiveness**: DLP policy activity analysis and audit log monitoring
- **Network Impact**: Bandwidth consumption and cloud service communication monitoring
- **Consolidated Reporting**: Unified KPI dashboard with trend analysis and recommendations

## 📁 Repository Structure

```
DLP-Performance-Monitoring/
├── Master-DLPMonitoring.ps1           # Master orchestration script
├── Check-DLPEventLogs.ps1             # Event log analysis with DLP classification
├── Check-DLPEndpointPerformance.ps1   # System resource impact monitoring
├── Check-DLPFileAppLatency.ps1        # File operation latency testing
├── Check-DLPPolicyActivity.ps1        # Policy activity and audit analysis
├── Check-DLPNetworkImpact.ps1         # Network overhead and bandwidth analysis
├── Check-DLPUserExperience.ps1        # End-user workflow impact assessment
└── README.md                          # This file
```

## ⭐ Key Menu System Improvements (v2.1)

### Enhanced User Experience
- **🎯 Zero Learning Curve**: No need to memorize parameters or script names
- **📋 Guided Selection**: Clear descriptions with duration estimates and recommendations
- **🔧 Flexible Operation**: Menu-driven for interactive use, parameter-based for automation
- **✅ Validation Built-In**: Prevents invalid selections and provides helpful error messages
- **📊 Export Integration**: Automated CSV report prompting with clear explanations

### Enterprise-Ready Features
- **🏢 Backward Compatibility**: All existing parameter combinations continue to work
- **⚡ Automation Support**: `-SkipMenu` parameter for scheduled tasks and SIEM integration
- **🔄 Hybrid Operation**: Menu system can be bypassed or enhanced with additional parameters
- **🛡️ Robust Error Handling**: Graceful fallbacks when components are missing or fail
- **📈 Enhanced Reporting**: 14+ CSV files generated with comprehensive analysis

### Operational Benefits
- **⏱️ Time Estimation**: Clear duration estimates for planning monitoring windows
- **🎨 Visual Clarity**: Color-coded menus with component classifications (Essential/Optional)
- **🔍 Component Discovery**: Learn about available monitoring capabilities through menu descriptions
- **📋 Parameter Tips**: Menu displays equivalent command-line usage for automation reference
- **🎯 Focus Selection**: Choose specific monitoring areas without running unnecessary components

## 🎯 Interactive Menu System

### Menu-Driven Operation (New in v2.1)
The Master script now features a comprehensive interactive menu system for guided DLP monitoring:

```
================================================================================
   MICROSOFT PURVIEW DLP MONITORING SUITE
            Select Monitoring Configuration
================================================================================

  [1] Full Monitoring Suite
      Complete DLP health assessment across all components
      Components: 6 (DLP Policy Activity Analysis, Endpoint Performance Impact, 
                     File Operation Latency, Network Performance Impact, 
                     User Experience Monitoring, Event Log Analysis)
      Duration: 15-25 minutes
      Recommended for monthly comprehensive assessments

  [2] Essential Monitoring
      Core DLP health monitoring for routine checks
      Components: 4 (DLP Policy Activity Analysis, Endpoint Performance Impact, 
                     File Operation Latency, Event Log Analysis)
      Duration: 8-12 minutes
      Recommended for weekly health checks

  [3] Performance Impact Analysis
      Focus on system performance and user experience impact
      Components: 3 (Endpoint Performance Impact, File Operation Latency, 
                     Network Performance Impact)
      Duration: 10-15 minutes
      Use when investigating performance concerns

  [4] Policy & Health Analysis
      DLP policy effectiveness and operational health
      Components: 2 (DLP Policy Activity Analysis, Event Log Analysis)
      Duration: 5-8 minutes
      Quick policy compliance and health assessment

  [5] Individual Component Selection
      Choose specific monitoring components to run
      Duration: Variable based on selection
      Advanced users - customize your monitoring scope

  [6] Exit
      Cancel monitoring and exit

Would you like to export detailed CSV reports? [Y/N]: Y
Report export enabled - comprehensive CSV files will be generated

Select monitoring configuration [1-6]:
```

### Individual Component Selection
Advanced users can select specific monitoring components:

```
============================================================
   INDIVIDUAL COMPONENT SELECTION
============================================================

  [1] Endpoint Performance Impact [Essential]
      Script: Check-DLPEndpointPerformance.ps1
      KPIs: CPU Impact, Memory Usage, Disk I/O

  [2] Event Log Analysis [Essential]  
      Script: Check-DLPEventLogs.ps1
      KPIs: Error Rate, Warning Rate, Agent Health

  [3] File Operation Latency [Essential]
      Script: Check-DLPFileAppLatency.ps1
      KPIs: File Open Delay, Save Delay, Copy/Move Delay

  [4] Network Performance Impact [Optional]
      Script: Check-DLPNetworkImpact.ps1
      KPIs: Network Overhead, Upload Delay, Sync Impact

  [5] DLP Policy Activity Analysis [Essential]
      Script: Check-DLPPolicyActivity.ps1
      KPIs: Policy Coverage, Match Rate, Enforcement Rate (requires authentication)

  [6] User Experience Monitoring [Optional]
      Script: Check-DLPUserExperience.ps1
      KPIs: User Satisfaction, Workflow Disruption, Training Effectiveness

Select components [1-6 or comma-separated]: 1,3,5
```

**Selection Methods:**
- **Single Selection**: Choose individual components (e.g., "4")
- **Multi-Selection**: Comma-separated list (e.g., "1,3,5")
- **Preset Options**: All Essential or All Components
- **Back Navigation**: Return to main menu anytime

### Menu System Benefits
- **User-Friendly**: No need to memorize parameters or component names
- **Guided Experience**: Clear descriptions and recommendations for each option
- **Flexible Selection**: From preset profiles to individual component choice
- **Export Integration**: Automated prompting for CSV report generation
- **Parameter Discovery**: Shows command-line alternatives for automation
- **Validation**: Prevents invalid selections with helpful error messages

## 🔧 Core Components

### 1. Master-DLPMonitoring.ps1
**Enterprise orchestration script** with **interactive menu system** that coordinates all monitoring components with guided configuration.

**Enhanced Features:**
- **Interactive Menu System**: User-friendly guided selection with component descriptions
- **Individual Component Selection**: Choose specific monitoring scripts to run
- **Export Report Prompting**: Automated CSV export with user confirmation
- **Monitoring Modes**: Full, Essential, Performance, Policy, Custom
- **Automated Execution**: Runs all components with unified reporting
- **KPI Consolidation**: Cross-component health assessment with executive summaries
- **Error Handling**: Robust execution with failure recovery and graceful fallbacks
- **Flexible Configuration**: Customizable duration, export options, quick test modes

**Interactive Menu Usage (Recommended):**
```powershell
# Menu-driven selection with guided configuration
.\Master-DLPMonitoring.ps1

# Menu with export reports pre-enabled
.\Master-DLPMonitoring.ps1 -ExportReports
```

**Direct Parameter Usage (Advanced):**
```powershell
# Full monitoring suite with comprehensive reporting
.\Master-DLPMonitoring.ps1 -MonitoringMode Full -ExportReports -UserPrincipalName user@domain.com

# Essential monitoring with quick test
.\Master-DLPMonitoring.ps1 -MonitoringMode Essential -Duration 5 -QuickTest

# Skip menu for automation scenarios
.\Master-DLPMonitoring.ps1 -MonitoringMode Performance -Duration 15 -SkipMenu
```

**Menu System Features:**
- **Guided Selection**: Clear descriptions of each monitoring mode with duration estimates
- **Component Details**: Shows which scripts will run and their KPI categories
- **Export Configuration**: Interactive prompt for CSV report generation
- **Individual Selection**: Custom component picker with multi-select capability
- **Parameter Tips**: Displays command-line alternatives for automation

### 2. Check-DLPEventLogs.ps1
**Advanced event log analyzer** with intelligent classification of DLP-related vs. system maintenance errors.

**Key Features:**
- **Smart Classification**: Distinguishes DLP errors from Intel/Dell hardware issues
- **Error Type Analysis**: Detailed technical analysis of Sense errors (101, 405, etc.)
- **Business Impact Assessment**: Severity classification with actionable recommendations
- **KPI Compliance**: Accurate DLP error rate calculation (excludes non-DLP issues)
- **Priority Action Plans**: Automated generation of prioritized remediation steps

**Technical Analysis:**
- Event ID 101: Network Detection & Response startup failures
- Event ID 405: Authentication service communication issues
- Event ID 7043: Service shutdown timing (cosmetic)
- Non-DLP separation: Intel TACD, Dell services, hardware detection

**Usage:**
```powershell
# Complete analysis with comprehensive reports
.\Check-DLPEventLogs.ps1 -ExportReports -ShowEventSamples -Days 7

# Quick health check
.\Check-DLPEventLogs.ps1 -Days 3
```

### 3. Check-DLPEndpointPerformance.ps1
**Real-time system resource monitoring** for DLP-related processes and services.

**Monitored Processes:**
- MsSense.exe (Microsoft Defender for Endpoint)
- SenseNdr (Network Detection & Response)
- MpDefenderCoreService (Core protection service)
- Related Windows Defender components

**Performance Metrics:**
- **CPU Usage**: Process-level and system impact
- **Memory Consumption**: Working set and private bytes
- **Disk I/O**: Read/write operations and throughput
- **Process Responsiveness**: Service availability and restart frequency

**KPI Thresholds:**
- CPU usage < 10% sustained
- Memory usage < 500MB per process
- Disk I/O < 50MB/min sustained
- Service availability > 99%

**Usage:**
```powershell
# 10-minute detailed monitoring
.\Check-DLPEndpointPerformance.ps1 -Duration 10 -ExportReports

# Quick 2-minute assessment
.\Check-DLPEndpointPerformance.ps1 -QuickTest
```

### 4. Check-DLPFileAppLatency.ps1
**File operation latency testing** to measure real-world user experience impact.

**Test Operations:**
- **File Open**: Time to open documents with DLP scanning
- **File Save**: Save operation delays with content analysis
- **Copy/Move**: File transfer operations with DLP inspection
- **Application Startup**: Impact on common applications (Office, Notepad, etc.)

**Test Methodology:**
- Creates test files with various sizes and content types
- Measures baseline vs. DLP-enabled performance
- Statistical analysis with confidence intervals
- Real-world scenario simulation

**KPI Thresholds:**
- File open delay < 2 seconds
- Save operation delay < 3 seconds
- Copy/move delay < 5 seconds
- Application startup delay < 10 seconds

**Usage:**
```powershell
# Comprehensive latency testing
.\Check-DLPFileAppLatency.ps1 -TestFileCount 20 -IncludeAppStartup -ExportReports

# Quick assessment
.\Check-DLPFileAppLatency.ps1 -QuickTest
```

### 5. Check-DLPPolicyActivity.ps1
**Microsoft Purview DLP policy monitoring** with comprehensive audit log analysis.

**Analysis Capabilities:**
- **Policy Effectiveness**: Match rates, false positives, business impact
- **Activity Trends**: Daily/weekly policy trigger patterns
- **User Impact**: Most affected users and content types
- **Workload Coverage**: Exchange, SharePoint, OneDrive, Teams, Endpoint analysis
- **Alternative Audit Methods**: Fallback data collection when Search-UnifiedAuditLog has limitations

**Authentication Support:**
- Microsoft Graph API integration
- Exchange Online PowerShell
- Security & Compliance PowerShell
- Dual connection support for comprehensive data access

**KPI Metrics:**
- Policy match accuracy > 90%
- False positive rate < 5%
- User workflow disruption < 10%
- Policy coverage across all workloads

**Usage:**
```powershell
# Complete policy analysis
.\Check-DLPPolicyActivity.ps1 -UserPrincipalName admin@domain.com -Days 14 -ExportReports -ShowDetailedPolicies

# Performance optimized analysis
.\Check-DLPPolicyActivity.ps1 -UserPrincipalName admin@domain.com -PerformanceMode -UseAlternativeAuditMethod
```

### 6. Check-DLPNetworkImpact.ps1
**Network performance impact analysis** for DLP cloud communications and scanning operations.

**Monitoring Areas:**
- **Bandwidth Consumption**: DLP-related traffic measurement
- **Cloud Classification**: Microsoft classifier service communication
- **Upload Scanning**: File upload delay analysis
- **Sync Operations**: OneDrive/SharePoint sync impact
- **Service Communications**: Microsoft Defender ATP telemetry and policy updates

**Network Metrics:**
- Background bandwidth usage
- Upload scanning delays
- Sync operation performance
- Cloud service response times

**KPI Thresholds:**
- Background traffic < 1% of available bandwidth
- Upload scanning delay < 30 seconds
- Sync operation impact < 20%
- Service communication latency < 5 seconds

**Usage:**
```powershell
# Comprehensive network analysis
.\Check-DLPNetworkImpact.ps1 -MonitorDurationMinutes 15 -IncludeSyncTest -ExportReports

# Quick network assessment
.\Check-DLPNetworkImpact.ps1 -QuickTest
```

### 7. Check-DLPUserExperience.ps1
**End-user workflow impact assessment** with realistic DLP policy testing.

**Test Scenarios:**
- **Document Creation**: Real content with DLP triggers (PII, financial data)
- **Email Operations**: Sending/receiving sensitive content
- **File Sharing**: Internal and external sharing workflows
- **Application Integration**: Office 365, PDF readers, browsers
- **Policy Notifications**: User notification effectiveness and timing

**Experience Metrics:**
- Workflow completion time
- User notification clarity
- False positive impact
- Training effectiveness
- Overall user satisfaction

**Usage:**
```powershell
# Complete user experience testing
.\Check-DLPUserExperience.ps1 -CollectSurveyData -TestAllScenarios

# Quick workflow assessment
.\Check-DLPUserExperience.ps1 -QuickTest
```

## 🎯 Key Features

### Enterprise-Grade Monitoring
- **Microsoft-Approved KPIs**: All thresholds based on official Microsoft guidance
- **Production-Ready**: Designed for enterprise environments with minimal system impact
- **Comprehensive Coverage**: Monitors all aspects of DLP deployment health

### Intelligent Analysis
- **Smart Error Classification**: Automatically separates DLP issues from system maintenance
- **Root Cause Analysis**: Detailed technical analysis with specific remediation steps
- **Business Impact Assessment**: Severity classification with operational impact evaluation

### Advanced Reporting
- **Unified KPI Dashboard**: Cross-component health assessment with trend analysis
- **Detailed CSV Exports**: Granular data for further analysis and trending
- **Executive Summaries**: High-level health reports for management consumption
- **Technical Deep-Dives**: Detailed analysis for IT professionals

### Flexible Execution
- **Multiple Monitoring Modes**: Full, Essential, Performance, Policy configurations
- **Configurable Duration**: Adjustable monitoring periods for different scenarios
- **Quick Test Options**: Abbreviated tests for rapid health checks
- **Automated Scheduling**: Suitable for scheduled monitoring and alerting

## 🛠️ Requirements

### System Requirements
- **Operating System**: Windows 10/11, Windows Server 2016+
- **PowerShell**: Version 5.1 or higher
- **Permissions**: Local administrator rights for performance monitoring
- **Network**: Internet connectivity for Microsoft 365 services

### Microsoft 365 Requirements
- **Microsoft Purview**: Active DLP policies and licensing
- **Microsoft Defender for Endpoint**: Endpoint DLP functionality enabled
- **Admin Permissions**: Security Administrator or Compliance Administrator roles
- **PowerShell Modules**: 
  - Microsoft.Graph (for policy analysis)
  - ExchangeOnlineManagement (for audit logs)
  - Microsoft.PowerShell.Security (for compliance connections)

### Optional Components
- **OneDrive**: For file sync impact testing
- **Office Applications**: For application startup latency testing
- **Network Monitoring Tools**: For advanced bandwidth analysis

## 🚀 Quick Start

### 1. Menu-Driven Operation (Recommended)
```powershell
# Interactive menu with guided configuration
.\Master-DLPMonitoring.ps1
```
**What happens:**
1. **Export prompt**: Choose whether to generate detailed CSV reports
2. **Monitoring menu**: Select from 6 predefined monitoring configurations
3. **Component details**: See which scripts will run and estimated duration
4. **Execution**: Automated coordination of all selected components
5. **Results**: Unified KPI assessment with executive summaries

### 2. Direct Parameter Usage (Advanced Users)
```powershell
# Essential monitoring with reports (most common)
.\Master-DLPMonitoring.ps1 -MonitoringMode Essential -ExportReports

# Complete assessment with authentication
.\Master-DLPMonitoring.ps1 -MonitoringMode Full -Duration 15 -ExportReports -UserPrincipalName admin@yourdomain.com

# Performance troubleshooting focus
.\Master-DLPMonitoring.ps1 -MonitoringMode Performance -Duration 20 -QuickTest

# Automation-friendly execution
.\Master-DLPMonitoring.ps1 -MonitoringMode Essential -SkipMenu -ExportReports
```

### 3. Individual Component Testing
```powershell
# Menu-driven component selection
.\Master-DLPMonitoring.ps1
# Select option [5] Individual Component Selection
# Choose specific components: "1,3" for Performance + File Latency

# Direct component execution (classic method)
.\Check-DLPEventLogs.ps1 -ExportReports -Days 7
.\Check-DLPEndpointPerformance.ps1 -Duration 10 -QuickTest
```

### 4. First-Time Setup and Validation
```powershell
# Clone or download the repository
git clone https://github.com/yourusername/dlp-performance-monitoring.git
cd dlp-performance-monitoring

# Ensure execution policy allows script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 2. Basic Health Check
```powershell
# Run essential monitoring (recommended for first-time use)
.\Master-DLPMonitoring.ps1 -MonitoringMode Essential -QuickTest -ExportReports
```

### 3. Full Enterprise Assessment
```powershell
# Complete monitoring suite with detailed reporting
.\Master-DLPMonitoring.ps1 -MonitoringMode Full -Duration 15 -ExportReports -UserPrincipalName admin@yourdomain.com
```

### 4. Scheduled Monitoring
```powershell
# Weekly automated monitoring (suitable for Task Scheduler)
.\Master-DLPMonitoring.ps1 -MonitoringMode Essential -Duration 10 -ExportReports -UserPrincipalName monitor@yourdomain.com
```

## 📊 Sample Output

### Master Suite Execution Summary
```
MONITORING SUITE EXECUTION SUMMARY
============================================================

Execution Results:
  Total Components: 6
  Successful: 6
  Failed: 0
  Total Duration: 12.3 minutes

Component Results:
  Event Log Analysis: Success (2.1 seconds)
  Endpoint Performance: Success (601.2 seconds)
  File Latency Testing: Success (45.7 seconds)
  Policy Activity Analysis: Success (23.4 seconds)
  Network Impact Assessment: Success (89.6 seconds)
  User Experience Monitoring: Success (67.8 seconds)

[+] Overall Monitoring Health: Healthy (100% success rate)
```

### DLP Event Log Analysis
```
DLP-FOCUSED KPI ASSESSMENT
============================================================
DLP Event Analysis Summary:
  Total DLP Events Analysed: 4180
  DLP-Related Errors: 36
  Non-DLP System Errors: 95 (excluded from DLP KPIs)

DLP KPI Results:
[+] Met DLP Error Rate: 0.86% (Target: < 2%)
[+] Met Warning Rate: 0.14% (Target: < 10%)
[+] Met Critical Event Rate: 0% (Target: < 0.5%)
[+] Met Policy Sync Failure Rate: 0% (Target: < 2%)
[+] Met Agent Health: 100% (Target: > 95%)

[+] Overall DLP Health: Healthy (6/6 KPIs passed, 100%)
```

### Performance Impact Assessment
```
DLP ENDPOINT PERFORMANCE MONITOR
============================================================
System Impact Summary:
  Average CPU Usage: 3.2%
  Peak Memory Usage: 245 MB
  Disk I/O Impact: 12 MB/min
  Process Availability: 99.8%

[+] All performance KPIs within Microsoft thresholds
```

## 📈 KPI Thresholds & Standards

All KPI thresholds are based on Microsoft's official guidance and enterprise best practices:

### Event Log Health
- **DLP Error Rate**: < 2% of DLP operations
- **Warning Rate**: < 10% of daily events
- **Critical Events**: < 0.5% of daily events
- **Agent Health**: > 95% availability
- **Policy Sync Success**: > 98%

### Performance Impact
- **CPU Usage**: < 10% sustained average
- **Memory Usage**: < 500MB per DLP process
- **Disk I/O**: < 50MB/min sustained
- **Service Availability**: > 99%

### User Experience
- **File Operation Delay**: < 3 seconds average
- **Application Startup**: < 10 seconds additional delay
- **Workflow Disruption**: < 10% of user operations
- **False Positive Rate**: < 5%

### Network Impact
- **Background Bandwidth**: < 1% of available bandwidth
- **Upload Scanning**: < 30 seconds delay
- **Cloud Communication**: < 5 seconds latency
- **Sync Impact**: < 20% performance reduction

## 🔍 Troubleshooting

### Common Issues

**Authentication Failures:**
```powershell
# Verify Microsoft Graph permissions
Connect-MgGraph -Scopes "Policy.Read.All", "AuditLog.Read.All"

# Test Exchange Online connection
Connect-ExchangeOnline -UserPrincipalName admin@domain.com
```

**Performance Monitoring Issues:**
```powershell
# Run as Administrator for process access
# Check if DLP services are running
Get-Service | Where-Object {$_.Name -like "*Sense*" -or $_.Name -like "*Defender*"}
```

**OneDrive Path Issues:**
```powershell
# Scripts automatically handle long paths with junctions
# Manual junction creation if needed:
mklink /J C:\TEMP_DLP "C:\Users\User\OneDrive\Long\Path"
```

### Performance Optimization

**For Large Environments:**
- Use `-PerformanceMode` for faster policy analysis
- Reduce monitoring duration for quick assessments
- Use `-QuickTest` for rapid health checks
- Schedule monitoring during off-peak hours

**For Detailed Analysis:**
- Increase monitoring duration to 15-30 minutes
- Enable all export options for trend analysis
- Use full monitoring mode for comprehensive assessment
- Run individual components for focused analysis

## 📝 Advanced Configuration

### Master Script Parameters (Enhanced)
The Master script supports comprehensive parameter control for both menu and direct execution:

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `-MonitoringMode` | String | Monitoring configuration (Full, Essential, Performance, Policy, Custom) | `-MonitoringMode Essential` |
| `-Duration` | Integer | Performance monitoring duration in minutes | `-Duration 15` |
| `-ExportReports` | Switch | Enable comprehensive CSV report export | `-ExportReports` |
| `-QuickTest` | Switch | Run accelerated tests for rapid assessment | `-QuickTest` |
| `-UserPrincipalName` | String | UPN for policy activity authentication | `-UserPrincipalName admin@domain.com` |
| `-ScriptDirectory` | String | Directory containing monitoring scripts | `-ScriptDirectory "C:\Scripts"` |
| `-IncludeUserSurvey` | Switch | Include user experience survey collection | `-IncludeUserSurvey` |
| `-Interactive` | Switch | Force confirmation prompts even with parameters | `-Interactive` |
| `-SkipMenu` | Switch | Skip interactive menu for automation scenarios | `-SkipMenu` |

### Menu System Customization
Modify monitoring profiles by editing the Master script's configuration section:

```powershell
# Define custom monitoring profiles
$monitoringProfiles = @(
    @{
        Index = 1
        Name = "CustomProfile"
        DisplayName = "Custom Security Focus"
        Description = "Tailored monitoring for security scenarios"
        Components = @("PolicyActivity", "EventLogs", "UserExperience")
        EstimatedDuration = "10-15 minutes"
        Recommendation = "Use for security incident investigation"
    }
)

# Customize component descriptions
$MonitoringComponents = @{
    "CustomComponent" = @{
        ScriptName = "Check-CustomDLP.ps1"
        Description = "Custom DLP Component Analysis"
        KPICategories = @("Custom KPI", "Security Metrics")
        Essential = $true
        RequiresAuth = $false
    }
}
```

### Automation Integration
The menu system integrates seamlessly with automation while maintaining backward compatibility:

```powershell
# Task Scheduler integration
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\DLP-Monitoring\Master-DLPMonitoring.ps1 -MonitoringMode Essential -SkipMenu -ExportReports"
$Trigger = New-ScheduledTaskTrigger -Daily -At "06:00"
Register-ScheduledTask -TaskName "DLP-Menu-Daily-Monitoring" -Action $Action -Trigger $Trigger

# SIEM integration with parameter bypass
.\Master-DLPMonitoring.ps1 -MonitoringMode Performance -Duration 5 -SkipMenu -QuickTest | Out-File -FilePath "C:\Logs\DLP-Health.log"

# PowerShell Desired State Configuration
Configuration DLPMonitoring {
    Script RunDLPMonitoring {
        SetScript = {
            & "C:\Scripts\Master-DLPMonitoring.ps1" -MonitoringMode Essential -SkipMenu -ExportReports
        }
        TestScript = { $false }  # Always run
        GetScript = { @{} }
    }
}
```

### Custom KPI Thresholds
Modify KPI thresholds in each script's configuration section:
```powershell
$EventLogKPIs = @{
    ErrorRate = 2.0                    # < 2% of DLP operations
    WarningThreshold = 10.0            # < 10% warning events per day
    PolicySyncFailures = 2.0           # < 2% policy sync failures
    AgentHealthThreshold = 95.0        # > 95% agent availability
}
```

### Menu Display Customization
Customize menu appearance and behavior:
```powershell
# Color scheme configuration
$Colors = @{
    Header = 'Cyan'
    Success = 'Green'
    Warning = 'Yellow'
    Error = 'Red'
    Info = 'White'
    Progress = 'Magenta'
}

# Menu timing and behavior
$MenuSettings = @{
    ShowComponentDetails = $true        # Display component scripts and KPIs
    ShowDurationEstimates = $true       # Display estimated execution times
    ShowRecommendations = $true         # Display usage recommendations
    AutoPromptExports = $true           # Automatically ask about report export
    ValidateComponents = $true          # Check script availability before execution
}
```

### Scheduling with Task Scheduler
Create automated monitoring with Windows Task Scheduler:
```powershell
# Example scheduled task for daily monitoring
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\DLP-Monitoring\Master-DLPMonitoring.ps1 -MonitoringMode Essential -ExportReports"
$Trigger = New-ScheduledTaskTrigger -Daily -At "06:00"
$Settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2)
Register-ScheduledTask -TaskName "DLP-Daily-Monitoring" -Action $Action -Trigger $Trigger -Settings $Settings -User "DOMAIN\ServiceAccount" -Password "Password"
```

### Integration with Monitoring Systems
Export CSV data can be integrated with:
- **SIEM Systems**: Import CSV data for alerting and dashboards
- **Power BI**: Create executive dashboards from exported data
- **Azure Monitor**: Send metrics to Azure for cloud-based monitoring
- **System Center**: Integration with SCOM for enterprise monitoring

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository** and create a feature branch
2. **Follow PowerShell best practices** and maintain UK English spelling
3. **Include comprehensive help** with examples for new functions
4. **Test thoroughly** in enterprise environments
5. **Update documentation** for any new features or changes
6. **Submit pull requests** with detailed descriptions

### Development Standards
- Use approved verb-noun PowerShell naming conventions
- Include comprehensive error handling and validation
- Maintain backward compatibility where possible
- Follow the existing code style and formatting
- Include unit tests for new functionality

## 📄 License

This project is licensed under the Apache 2.0 License with Commons Clause - see the [LICENSE](LICENSE) file for details.

### Key License Points:
- **Commercial Use**: Permitted with restrictions
- **Modification**: Allowed with attribution
- **Distribution**: Permitted with license inclusion
- **Private Use**: Fully permitted
- **Selling Prohibited**: Commons Clause restriction

## 🙋 Support

### Documentation
- **Script Help**: Use `Get-Help .\ScriptName.ps1 -Full` for detailed documentation
- **Parameter Guidance**: All scripts include comprehensive parameter help
- **Example Usage**: Multiple examples provided for each script

### Community Support
- **Issues**: Report bugs and request features via GitHub Issues
- **Discussions**: Join community discussions for best practices
- **Wiki**: Additional documentation and use cases

### Enterprise Support
For enterprise deployments and custom requirements:
- **Professional Services**: Available for implementation and customization
- **Training**: PowerShell and DLP monitoring best practices
- **Consulting**: Architecture guidance and optimization

## 🏷️ Version History

### Version 2.1 (Current) - Interactive Menu System Release
- **🎯 Interactive Menu System**: Complete menu-driven operation with guided configuration
- **🔧 Individual Component Selection**: Choose specific monitoring scripts with multi-select capability
- **📊 Enhanced Export Integration**: Automated CSV export prompting with user confirmation
- **⚙️ Advanced Parameter Handling**: Skip menu options for automation while maintaining menu functionality
- **🎨 User Experience Improvements**: Color-coded menus, duration estimates, and component descriptions
- **🔄 Flexible Execution Modes**: Menu-driven, parameter-based, and hybrid operation modes
- **📈 Enhanced Reporting**: Master script generates 3 consolidated CSV reports plus individual component exports
- **🛡️ Robust Error Handling**: Graceful fallbacks and improved validation for menu selections

### Version 2.0 - Advanced Analysis Release
- **🧠 Enhanced Error Classification**: Intelligent DLP vs. system error separation
- **📋 Comprehensive Error Type Analysis**: Detailed business impact assessments
- **🎯 Priority Action Plans**: Automated recommendations with severity classification
- **📊 Improved CSV Exports**: Detailed analysis data with trend information
- **🏢 Master Suite Orchestration**: Consolidated reporting across all components

### Version 1.0 - Foundation Release
- **📊 Initial Release**: Core monitoring capabilities established
- **📝 Basic Event Log Analysis**: Fundamental DLP health monitoring
- **⚡ Performance Monitoring Foundation**: System resource impact measurement
- **📁 File Latency Testing**: File operation delay analysis
- **🔍 Policy Activity Monitoring**: Initial DLP policy effectiveness tracking

## 🎖️ Acknowledgments

- **Microsoft**: For comprehensive DLP and Defender for Endpoint documentation
- **PowerShell Community**: For best practices and development standards
- **Enterprise Customers**: For real-world testing and feedback
- **Security Community**: For guidance on monitoring best practices

---

**Developed by JJ Milner | Global Micro Solutions**  
**Enterprise-grade Microsoft Purview DLP monitoring solutions**