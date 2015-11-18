
@echo off
rem CDDL HEADER START
rem
rem The contents of this file are subject to the terms of the
rem Common Development and Distribution License, Version 1.0 only
rem (the "License").  You may not use this file except in compliance
rem with the License.
rem
rem You can obtain a copy of the license at
rem trunk/opends/resource/legal-notices/OpenDS.LICENSE
rem or https://OpenDS.dev.java.net/OpenDS.LICENSE.
rem See the License for the specific language governing permissions
rem and limitations under the License.
rem
rem When distributing Covered Code, include this CDDL HEADER in each
rem file and include the License file at
rem trunk/opends/resource/legal-notices/OpenDS.LICENSE.  If applicable,
rem add the following below this CDDL HEADER, with the fields enclosed
rem by brackets "[]" replaced with your own identifying information:
rem      Portions Copyright [yyyy] [name of copyright owner]
rem
rem CDDL HEADER END
rem
rem
rem      Portions Copyright 2006-2007 Sun Microsystems, Inc.

setlocal

rem check that the path does not contain the ^% character which breaks
rem the batch files.
for %%i in (%~sf0) do set NON_ESCAPED=%%~dPsi..


FOR /F "tokens=1-2* delims=%%" %%1 IN ("%NON_ESCAPED%") DO (
if NOT "%%2" == "" goto invalidPath)

for %%i in (%~sf0) do set DIR_HOME=%%~dPsi.

set INSTANCE_ROOT=%DIR_HOME%

:checkOpenDSJavaBin
if "%OPENDS_JAVA_BIN%" == "" goto checkOpenDSJavaHome
goto setClassPath

:checkOpenDSJavaHome
if "%OPENDS_JAVA_HOME%" == "" goto checkOpenDSJavaHomeFile
if not exist "%OPENDS_JAVA_HOME%\bin\java.exe" goto checkOpenDSJavaHomeFile
set OPENDS_JAVA_BIN=%OPENDS_JAVA_HOME%\bin\java.exe
goto setClassPath

:checkOpenDSJavaHomeFile
if not exist "%DIR_HOME%\lib\set-java-home.bat" goto checkJavaBin
call "%DIR_HOME%\lib\set-java-home.bat"
if not exist "%OPENDS_JAVA_HOME%\bin\java.exe" goto checkJavaBin
set OPENDS_JAVA_BIN=%OPENDS_JAVA_HOME%\bin\java.exe
goto setClassPath

:checkJavaBin
if "%JAVA_BIN%" == "" goto checkJavaHome
set OPENDS_JAVA_BIN=%JAVA_BIN%
goto setClassPath

:checkJavaHome
if "%JAVA_HOME%" == "" goto noJavaHome
if not exist "%JAVA_HOME%\bin\java.exe" goto noJavaHome
set OPENDS_JAVA_BIN=%JAVA_HOME%\bin\java.exe
goto setClassPath

:noJavaHome
echo Error: OPENDS_JAVA_HOME environment variable is not set.
echo        Please set it to a valid Java 5 (or later) installation.
pause
goto end

:invalidPath
echo Error: The current path contains a %% character.  OpenDS cannot
echo        be installed on a path containing this character.
pause
goto end

:noValidJavaHome
echo ERROR:  The detected Java version could not be used.  Please set 
echo         OPENDS_JAVA_HOME to to a valid Java 5 (or later) installation.
pause
goto end

:setClassPath
FOR %%x in ("%DIR_HOME%\lib\*.jar") DO call "%DIR_HOME%\lib\setcp.bat" %%x
set CLASSPATH=%DIR_HOME%\classes;%CLASSPATH%

set PATH=%SystemRoot%

rem Test that the provided JDK is 1.5 compatible.
"%OPENDS_JAVA_BIN%" org.opends.server.tools.InstallDS -t > NUL 2>&1
if not %errorlevel% == 0 goto noValidJavaHome

if "%~1" == "" goto callLaunch
goto callJava

:callLaunch
"%DIR_HOME%\lib\winlauncher.exe" launch "%OPENDS_JAVA_BIN%" %JAVA_ARGS% org.opends.quicksetup.installer.SetupLauncher
goto end

:callJava
"%OPENDS_JAVA_BIN%" %JAVA_ARGS% org.opends.quicksetup.installer.SetupLauncher %*

rem return part
if %errorlevel% == 50 goto version
goto end

:version
rem version information was requested. Return code should be 0.
exit /B 0

:end

