REM
REM  runtest.bat
REM
REM  Author:
REM  	Laurent Le Guillermic (https://github.com/FFFF0h)
REM
REM  Copyright (c) 2016 Laurent Le Guillermic All rights reserved.
REM
REM  Licensed under the Apache License, Version 2.0 (the "License");
REM  you may not use this file except in compliance with the License.
REM  You may obtain a copy of the License at
REM
REM  http:REMwww.apache.org/licenses/LICENSE-2.0
REM
REM  Unless required by applicable law or agreed to in writing, software
REM  distributed under the License is distributed on an "AS IS" BASIS,
REM  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
REM  See the License for the specific language governing permissions and
REM  limitations under the License.
REM

REM Please set username, password and domain accordingly using the RunPSScript -hash option
SET username = 
SET password = 
SET domain = 

RunPSScript -help
echo test | RunPSScript -script .\helloInput.ps1 -version 3 -debug
echo test | RunPSScript -script .\helloInput.ps1 -version 3 -debug -elevated
echo test | RunPSScript -script .\helloInput.ps1 -version 3 -debug -username %username% -Password %password% -Domain %domain%
echo test | RunPSScript -script .\helloInput.ps1 -version 3 -debug -elevated -username %username% -Password %password% -Domain %domain%