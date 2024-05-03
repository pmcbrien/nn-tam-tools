# Script to check for required Microsoft Visual C++ Redistributable packages,
# IIS version and modules, and to provide guidance for Noname installation.
# Author: Patrick McBrien

# Output a message indicating the start of the check for Visual C++ Redistributable packages
Write-Host "`nCheck for Visual C++ Redistributable packages"
# Initialize a hash table to track whether specific Visual C++ Redistributable packages are found
$PackagesFound = @{
    "2015-2022x64" = $False;  # Set the default status of the required package
}
# Variables to represent the year and architecture for the Visual C++ Redistributable
$Year = "2015-2022"
$Architecture = "x64"
# Search for installed Visual C++ Redistributable packages in the Windows Registry
& {
    # Check the 32-bit and 64-bit registry for installed packages
    #Write-Host "`nCheck the 32-bit and 64-bit registry for installed packages"
    Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*
    Get-ChildItem HKLM:\SOFTWARE\WoW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
} | ForEach-Object { 
    # Get the display name of each package
    $CurDisplayName = $_.GetValue("DisplayName")
    # Check if the display name matches the expected pattern for Visual C++ Redistributable
    if( $CurDisplayName -match "^Microsoft Visual C\+\+\D*(?<Year>(\d|-){4,9}).*Redistributable.*") {
        # Extract the year and architecture from the display name
        $Year = $Matches.Year
        [Void] ($CurDisplayName -match "(?<Arch>(x86|x64))")
        $Architecture = $Matches.Arch
        
        # Update the hash table to indicate the package was found
        $PackagesFound[ '' + $Year + $Architecture ] = $True
    }
}
# Check if all required Visual C++ Redistributable packages are found
If ( $PackagesFound.Values -notcontains $False) {
    # If all required packages are found, indicate that installation can proceed
    Write-Host "`nSuccess: All required versions of Microsoft Visual C++ were found and Noname can be installed."
    $PackagesFound  # Output the hash table for further review
} Else {
    # If any required package is missing, do nothing (could be enhanced to add error handling)
    Write-Host "`nError: MS VC++ Not found. Please install learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist"
} 
# Output a message indicating the start of the check for IIS version and sites
Write-Host "`nCheck IIS Version Information as noname requires IIS 10"
Write-Host "`nYour current IIS Version is"

# Get and display the current IIS version from the registry
get-itemproperty HKLM:\SOFTWARE\Microsoft\InetStp\  | select setupstring,versionstring 
Write-Host "`nCheck for existing Noname Global Module installed on IIS"
# List all installed IIS Global Modules and check for existing Noname-related modules
$modules = Get-WebGlobalModule 
foreach ($module in $modules) {
    # If a Noname-related module is found, warn the user about potential conflicts
    If ($module.Name -match "Noname") {
        Write-Host "`nWe found a currently installed Global IIS Module that is related to Noname. You may want to uninstall this if this is a new installation."
        Write-Host "  - Module Name: $($module.Name)"
    }
}
# Output a message indicating that script execution has completed
Write-Host "`nScript execution completed."
 
