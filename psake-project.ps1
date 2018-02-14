Properties {
    $solution = "dashboard.Dashboard.Authorization.sln"
}

Include "packages\dashboard.Build.*\tools\psake-common.ps1"

Task Default -Depends Pack

Task Merge -Depends Compile -Description "Run ILMerge /internalize to merge assemblies." {
    Merge-Assembly "dashboard.Dashboard.Authorization" @("Microsoft.Owin")
}

Task Collect -Depends Merge -Description "Copy all artifacts to the build folder." {
    Collect-Assembly "dashboard.Dashboard.Authorization" "Net45"
}

Task Pack -Depends Collect -Description "Create NuGet packages and archive files." {
    $version = Get-BuildVersion
    Create-Package "dashboard.Dashboard.Authorization" $version
}