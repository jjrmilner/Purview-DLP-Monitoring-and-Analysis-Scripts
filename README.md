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

## 🔧 Core Components

### 1. Master-DLPMonitoring.ps1
**Enterprise orchestration script** that coordinates all monitoring components with configurable execution modes.

**Features:**
- **Monitoring Modes**: Full, Essential, Performance, Policy
- **Automated Execution**: Runs all components with unified reporting
- **KPI Consolidation**: Cross-component health assessment
- **Error Handling**: Robust execution with failure recovery
- **Flexible Configuration**: Customizable duration, export options, quick test modes

**Usage:**
```powershell
# Full monitoring suite (recommended)
.\Master-DLPMonitoring.ps1 -MonitoringMode Full -ExportReports -UserPrincipalName user@domain.com

# Essential monitoring only
.\Master-DLPMonitoring.ps1 -MonitoringMode Essential -Duration 5 -QuickTest

# Performance impact assessment
.\Master-DLPMonitoring.ps1 -MonitoringMode Performance -Duration 15
```

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

### 1. Initial Setup
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

## 📄 **License:** Apache 2.0 (see LICENSE)  
**Additional restriction:** Commons Clause (see COMMONS-CLAUSE.txt)

**SPDX headers**
- Each source file includes:  
  `SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause`

---

### FAQ: MSP and Consulting Use

**Q: Can an MSP or consultant use this tool in a paid engagement?**  
**A:** It depends on how the tool is used:  
- **Allowed:** If the tool is used internally by the end customer (e.g., installed in their tenant) and the consultant is simply assisting, this is generally acceptable.  
- **Not allowed without a commercial licence:** If the MSP or consultant provides a managed service where the tool runs in their own environment (e.g., their tenant or infrastructure) or if the value of the service substantially derives from the tool’s functionality, this falls under the definition of “Sell” in the Commons Clause and requires a commercial licence.

**Q: Why is this restricted?**  
The Commons Clause removes the right to “Sell,” which includes providing a service for a fee where the value derives from the software. This ensures fair use and prevents competitors from monetising the tool without contributing back.

**Q: How do I get a commercial licence?**  
Contact Global Micro Solutions (Pty) Ltd at:  
📧 licensing@globalmicro.co.za

---

## ⚠️ Warranty Disclaimer

Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. Please review the Apache-2.0 WITH Commons-Clause License for the specific language governing permissions and limitations under the License.

---


## 🏷️ Version History

### Version 2.1 (Current)
- Enhanced error classification with intelligent DLP vs. system separation
- Comprehensive error type analysis with business impact assessment
- Priority action plans with automated recommendations
- Improved CSV exports with detailed analysis data
- Master suite orchestration with consolidated reporting

### Version 2.0
- Added comprehensive DLP error type analysis
- Implemented smart classification system
- Enhanced KPI calculations and reporting
- Added business impact assessments
- Improved user experience monitoring

### Version 1.0
- Initial release with core monitoring capabilities
- Basic event log analysis
- Performance monitoring foundation
- File latency testing implementation
- Policy activity monitoring

## 🎖️ Acknowledgments

- **Microsoft**: For comprehensive DLP and Defender for Endpoint documentation
- **PowerShell Community**: For best practices and development standards
- **Enterprise Customers**: For real-world testing and feedback
- **Security Community**: For guidance on monitoring best practices

---

**Developed by JJ Milner | Global Micro Solutions**  
**Enterprise-grade Microsoft Purview DLP monitoring solutions**
