@title FiddlerImportNetLog Builder
@cd C:\src\FiddlerImportNetLog\installer
@C:\tools\signtool sign /as /d "Fiddler NetLog Importer" /du "https://textslashplain.com/" /n "Eric Lawrence" /tr http://timestamp.digicert.com /td SHA256 /fd SHA256 C:\src\FiddlerImportNetLog\FiddlerImportNetLog\bin\release\FiddlerImportNetLog.dll 
@filever C:\src\FiddlerImportNetLog\FiddlerImportNetLog\bin\release\FiddlerImportNetLog.dll > Addon.ver
@C:\src\NSIS\MakeNSIS.EXE /V3 FiddlerImportNetLog.nsi
@CHOICE /M "Would you like to sign?"
@if %ERRORLEVEL%==2 goto done
:sign
@C:\tools\signtool sign /as /d "Fiddler NetLog Importer" /du "https://textslashplain.com/" /n "Eric Lawrence" /tr http://timestamp.digicert.com /td SHA256 /fd SHA256 FiddlerImportNetLog.exe 
@if %ERRORLEVEL%==-1 goto sign
@:upload
@:done
@title Command Prompt