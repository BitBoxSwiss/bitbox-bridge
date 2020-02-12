OutFile "getVersion.exe"
SilentInstall silent
RequestExecutionLevel user

Section
	nsExec::ExecToStack '"toml-echo" ..\..\Cargo.toml package.version'
	Pop $0
	Pop $1
	StrCpy $2 "$1" -1 ; strip newline
	FileOpen $R0 "version.txt" w
		FileWrite $R0 '!define VERSION "$2.0"'
	FileClose $R0
SectionEnd

