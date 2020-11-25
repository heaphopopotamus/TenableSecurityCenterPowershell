function Get-SecurityCenterToken {
    <#
    .SYNOPSIS
        Queries a Tenable Security Center for an access token
    .DESCRIPTION
        The Get-SecurityCenterToken command queries Tenable Security Center for an access token.
        Documentation: https://docs.tenable.com/tenablesc/api/index.html
    #>
    Param (
        [string]$username,
        [string]$password,
        [string]$url
    )
    $LoginData = (ConvertTo-Json -compress @{username=$username; password=$password})
    $ret = Invoke-WebRequest -URI $url/rest/token -Method POST -Body $LoginData -UseBasicParsing -SessionVariable sv
    $token = (convertfrom-json $ret.Content).response.token
    return @($sv,$token) 
}
Export-ModuleMember -Function Get-SecurityCenterToken
function Get-SecurityCenterAnalysis {
    <#
    .SYNOPSIS
        Queries a Tenable Security Center for Vulnerability Analysis results
    .DESCRIPTION
        The Get-SecurityCenterAnalysis command queries Tenable Security Center fo vulnerability analysis results.
        A query can be passed in with given filters based on the Rest API.
        Documentation: https://docs.tenable.com/tenablesc/api/index.html
    #>
    Param (
        [string]$loginToken,
        [Microsoft.PowerShell.Commands.WebRequestSession]$session,
        [string]$query,
        [string]$sc_url
    )
    $ret = Invoke-WebRequest -URI $sc_url/rest/analysis -UseBasicParsing -Headers @{"X-SecurityCenter"="$loginToken"} -Body $query -Websession $session -Method Post
    $retobj = $ret.Content|ConvertFrom-Json
    Write-Output $retobj.response
}
Export-ModuleMember -Function Get-SecurityCenterAnalysis
function New-scFilter {
    <#
    .SYNOPSIS
        Builds the Security Center filter hashtable
    .DESCRIPTION
        The New-scFilter command creates a hashtable for the filter object of the
        Tenable Security Center query body.  
        Documentation: https://docs.tenable.com/tenablesc/api/index.html
    #>
    Param (
        [string]$filterName, 
        [string]$operator,
        [string]$value
    )
    return @{
        filterName = $filterName;
        operator = $operator;
        value = $value
    }
}
Export-ModuleMember -Function New-scFilter
function New-scQuery {
    <#
    .SYNOPSIS
        Builds the Security Center query hashtable
    .DESCRIPTION
        The New-scQuery command creates a hashtable for the query object of the
        Tenable Security Center query body.  
        Also pass in sourceType of cumulative or mitigated.  
        Documentation: https://docs.tenable.com/tenablesc/api/index.html
    #>
    Param (
        [System.Object]$filters,
        [string]$sourceType
        )
    $cumulative_post_hash = @{
        query= @{
            name = "";
            description = "";
            context = "";
            createdTime = 0;
            modifiedTime = 0;
            groups = @();
            type = "vuln";
            tool = "vulndetails";
            sourceType = $sourceType;
            startOffset = 0;
            endOffset = 50;
            filters = @()
        };
        sourceType = "cumulative";
        sortField = "severity";
        sortDir = "desc";
        columns = @();
        type = "vuln"
        }
        foreach ($filter in $filters) {
            $cumulative_post_hash.query.filters += $filter
        }
        return $cumulative_post_hash | ConvertTo-Json -Depth 3
}
Export-ModuleMember -Function New-scQuery
