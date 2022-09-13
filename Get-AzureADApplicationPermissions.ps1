[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    $FolderPath = "$env:USERPROFILE\Downloads",

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    $FileName = "$(Get-Date -f 'yyyy-MM-dd')-AzureADApplicationPermissions.csv"
) 

# Get all MS Graph permissions
$graphPermissions = Find-MgGraphPermission -All -Online

# Get all Enterprise Applications
$applications = Get-MgServicePrincipal -All

$output = foreach ($app in $applications) {

    # Get all delegated (scope) permissions
    # Run a loop as the Scopes object is returned as an array when there are permissions that have been consented as both an admin and a user
    Get-MgOauth2PermissionGrant -All -Filter "ClientId eq '$($app.Id)'" | ForEach-Object {

        # The scopes are returned as a space-separated list
        foreach ($scope in $_.Scope.Trim().Split(" ") ) {

            # Find the exact scope details from the Find-MgGraphPermission results
            $permission = $graphPermissions | Where-Object { $_.Name -eq $scope -and $_.PermissionType -eq "Delegated" }

            [PSCustomObject] @{
                PrincipalName     = $app.DisplayName
                PrincipalId       = $_.ClientId
                PrincipalType     = $app.ServicePrincipalType
                Type              = $null
                Publisher         = $app.AdditionalProperties.verifiedPublisher
                ResourceName      = (Get-MgServicePrincipal -ServicePrincipalId $_.ResourceId).DisplayName
                ResourceId        = $_.ResourceId
                PermissionName    = $permission.Name
                PermissionId      = $permission.Id
                PermissionType    = $permission.PermissionType
                PermissionConsent = $permission.Consent
                ConsentType       = $_.ConsentType
            }
        }
    }

    # Get all application (role) permissions
    $appPermissions = Get-MgServicePrincipalAppRoleAssignment -All -ServicePrincipalId $app.Id 

    foreach ($role in $appPermissions) {

        # Find the exact role details from the Find-MgGraphPermission results
        $permission = $graphPermissions | Where-Object { $_.Id -eq $perm.AppRoleId }

        [PSCustomObject] @{
            PrincipalName     = $role.PrincipalDisplayName
            PrincipalId       = $role.PrincipalId
            PrincipalType     = $role.PrincipalType
            Type              = $role.ObjectType
            Publisher         = $app.AdditionalProperties.verifiedPublisher
            ResourceName      = $role.ResourceDisplayName
            ResourceId        = $role.ResourceId
            PermissionName    = $permission.Name
            PermissionId      = $role.AppRoleId
            PermissionType    = $permission.PermissionType
            PermissionConsent = $permission.Consent
            ConsentType       = $null
        }
    }
}

# Export the results as a CSV file
$filePath = Join-Path $FolderPath -ChildPath $FileName

try
{
    $output | Sort-Object PrincipalName | Export-CSV $filePath -NoTypeInformation
    Write-Host "Export to $filePath succeeded" -ForegroundColor Cyan
}
catch
{
    Write-Error "Export to $filePath failed | $_ "
}