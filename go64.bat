@echo off

if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" amd64

if exist wsserver.exe del wsserver.exe

c:\harbour\bin\hbmk2 wsserver.hbp -comp=msvc64 -mt

if errorlevel 1 goto COMPILEERROR

if exist wsserver.exp del wsserver.exp 
if exist wsserver.lib del wsserver.lib

cls
wsserver.exe

goto EXIT

:COMPILEERROR

echo *** Error 

pause

:EXIT