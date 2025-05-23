#
# Module manifest for module 'PoshSYSI'
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'PoshSYSI.psm1'

# Version number of this module.
ModuleVersion = '0.3.1.0'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = 'bfb1c6a3-166c-43a8-92d2-ea18d407a2f1'

# Author of this module
Author = 'Daniel Zsiger'

# Company or vendor of this module
# CompanyName = 'Unknown'

# Copyright statement for this module
Copyright = '(c) 2021-2025 Daniel Zsiger. All rights reserved.'

# Description of the functionality provided by this module
Description = 'PoshSYSI retrieves detailed system information including hardware, operating system, and installed software from local or remote computers. It supports different levels of detail and can output reports to log files.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.1'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @('Get-PoshSYSI')

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
# VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('SystemInfo', 'Hardware', 'Software', 'Inventory', 'Reporting', 'CIM', 'PowerShell')

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/Kinsiinoo/PoshSYSI/blob/main/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/Kinsiinoo/PoshSYSI'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        ReleaseNotes = @"
Version 0.3.1.0:
- Implemented retrieval of installed programs from remote computers in 'Full' mode using Invoke-Command with CIM sessions.
- Introduced a standardized error handling mechanism (New-PoshSYSIErrorRecord) for more consistent and detailed error reporting.
- Ensured proper re-initialization of data structures for each local run and for every remote computer processed, preventing data carry-over.
- Added automatic normalization for ReportPath to ensure it ends with a backslash if it's a directory.
- Refined remote data fetching for OS installation date, Get-ComputerInfo, BitLocker status, and Windows License status using targeted Invoke-Command calls.
- Improved robustness of data collection with more granular try-catch blocks for different data categories (Minimal, Normal).

Version 0.3.0.0:
- Added optional ReportPath parameter for custom report output directory.
- Improved data collection performance using generic lists for Monitors and InstalledPrograms.
- Refactored Invoke-SYSIMode logic for clarity and efficiency.
- Enhanced remote connection handling using CIM sessions for most operations, improving reliability and performance.
- Implemented more robust and detailed error handling with a dedicated helper function.
- Updated comment-based help and inline comments for clarity and accuracy.
- Known issue: In 'Full' mode for remote computers, installed programs are currently retrieved from the machine running Get-PoshSYSI, not the remote target.
"@

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}
