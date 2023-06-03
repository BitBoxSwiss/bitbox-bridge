FOR /F "tokens=* USEBACKQ" %%F IN (`toml-echo ..\..\..\Cargo.toml package.version`) DO (
	SET VERSION=%%F
)
ECHO Packaging version %VERSION%
msbuild /p:Configuration=Debug /p:Platform=x64 /p:VERSION=%VERSION% /p:SignOutput=true project.wixproj
msbuild /p:Configuration=Debug /p:Platform=x64 /p:VERSION=%VERSION% /p:SignOutput=true bundle.wixproj
