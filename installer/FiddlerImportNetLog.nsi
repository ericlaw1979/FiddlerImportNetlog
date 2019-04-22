Name "Fiddler FiddlerNetLogImport"
OutFile "FiddlerImportNetLog.exe"
Icon "addon.ico"

RequestExecutionLevel "user"
SetCompressor /solid lzma
XPStyle on

!DEFINE /file VER_ADDON Addon.ver
!define /date NOW "%b-%d-%y"

BrandingText "[${NOW}] v${VER_ADDON}" 
VIProductVersion "${VER_ADDON}"
VIAddVersionKey "FileVersion" "${VER_ADDON}"
VIAddVersionKey "ProductName" "Fiddler NetLog Importer"
VIAddVersionKey "Comments" "https://textslashplain.com/"
VIAddVersionKey "LegalCopyright" "©2019 Eric Lawrence"
VIAddVersionKey "CompanyName" "Eric Lawrence"
VIAddVersionKey "FileDescription" "Installer for Fiddler Fiddler NetLog Importer"

InstallDir "$DOCUMENTS\Fiddler2\ImportExport\"

Section "Main" ; (default section)
SetOutPath "$INSTDIR"

SetOverwrite on
File "..\FiddlerImportNetLog\bin\release\FiddlerImportNetLog.dll"


MessageBox MB_OK "Installed Successfully$\n$\nRestart Fiddler to see the 'NetLog JSON' option inside 'File > Import Sessions'."

SectionEnd ; end of default section