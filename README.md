RunPSScript
===========

Runs a Powershell script or command using any version of PowerShell engine, scheduled at regular intervals, with elevated privileges and/or under any account.

About
-----
This tools was written primarily to execute monitoring PowerShell script within NxLog (http://nxlog-ce.sourceforge.net/). 
The source code is available at https://github.com/FFFF0h/RunPSScript.

Requires .Net Framework 3.5. Licensed under Apache 2.0.

Main Features
-------------
 * **Execute Powershell script or command** - Can execute PowerShell script block or file.
 * **Input Pipeline** - The input pipeline of RunPSScript is exposed to the PowerShell script as is.
 * **Output Pipeline** - The output pipeline of RunPSScript is the same one as the Powershell script.
 * **Elevated Privileges** - Can run the script with elevated privileges.
 * **Impersonation** - Can impersonate to a given user.
 * **Crypted Account Parameters** - Account related parameters are crypted and unique per system. No clear text domain, user name or password in config files.
 * **Scheduled Runs** - Can schedule runs at regular intervals.

Licenses
--------
| Module                   | Author                | License         |
|--------------------------|-----------------------|-----------------|
| RunPSScript              | Laurent Le Guillermic | 2016 Apache 2.0 |
| named-pipe-wrapper       | Andrew C. Dvorak      | 2013 MIT        |
| CSharpTest.Net.Processes | Roger Knapp           | 2014 Apache 2.0 |
| ProcessPrivileges        | Nick Lowe             | 2009 Copyright? |
| Task Parallel Library    | Jim Borden (Couchbase)| 2015 Apache 2.0 |


Example Usage
-------------
 * **Getting some help**
`C:\>RunPSScript -help
RunPSScript.exe - Run, schedule and elevate a PowerShell command - v1.0.0.0
Copyright (c) 2016 Laurent Le Guillermic. All rights reserved.

Usage:
echo hi | RunPSScript.exe -Script .\hello.ps1 [-Version (1|2|3)] [-Domain HashedADSLOCAL] [-UserName HashedJohn] [-Password HashedPwd] [-Elevated] [-Schedule 10] [-Silent] [-Debug]
RunPSScript.exe -Hash V3ryS3cureP4sswOrd
With:
        -Script         The PS script or command. Required.
        -Version        Powershell version 1, 2 or 3. Default is 2.
        -Domain         Hashed account domain name used to run the command.
        -UserName       Hashed account user name used to run the command.
        -Password       Hashed account password used to run the command.
        -Elevated       Runs the command with elevated privileges.
        -Schedule       Executes the command every x.x minutes.
        -Silent         Do not show any error messages.
        -Debug          Create a log file containing debug informations.
        -NoLogo         Starts without displaying the copyright banner.
        -Hash           Generate a system unique hashed string.`

* **Hash a password**
`C:\>RunPSScript -hash My_Super_Secure_Password`

* **Pipe in, Pipe out with exit code**
`C:\>echo "This is an input pipeline" | RunPSScript -script "& {$Input | %{ $_ }; Exit $LastExitCode; }"`

* **Execute a PS script with elevated privileges every 1min30sec and do not report errors**
`C:\>RunPSScript -script .\MyScript.ps1 -elevated -Schedule 1.5 -Silent`
