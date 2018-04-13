@echo off
set astyle="C:\AStyle\bin\astyle.exe"
REM recursively scan directory
for /r . %%a in (*.cc;*.c) do %astyle% -A3 -s -xn -xW -Y -p -H -U -k3 -W3 -j -c -xy -xL "%%a"
for /r . %%a in (*.hpp;*.h) do %astyle% -A3 -s -xn -xW -Y -p -H -U -k3 -W3 -j -c -xy -xL "%%a"
REM delete all backup file
for /r . %%a in (*.orig) do del "%%a"
pause