#
#  helloInput.ps1
#
#  Author:
#  	Laurent Le Guillermic (https://github.com/FFFF0h)
#
#  Copyright (c) 2016 Laurent Le Guillermic All rights reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

# Test script for RunPSScript.
# The script reads data from the pipe.

# Who am I ?
Write-Host "Current user: " -NoNewline
whoami

# Check Privileges
$wid = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$prp = new-object System.Security.Principal.WindowsPrincipal($wid)
$adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if ($prp.IsInRole($adm))
{
	Write-Host "Privileges: Elevated"
}
else
{
	Write-Host "Privileges: Standard"
}

# Get PS Apartment
Write-Host "Apartment is " -NoNewline
[System.Threading.Thread]::CurrentThread.GetApartmentState()

$PSVersionTable.PSVersion
Write-Host "Environment variables:"
gci env: | Select Name, Value

# Read the pipe
Write-Output "Reading the input pipe:"
foreach($line in $Input)
{
	Write-Output "$line"
}

# Do some long operation
Write-Host "Waiting..."
Start-Sleep -s 5

# Return code
Write-Output "Done!"
Exit 1234


