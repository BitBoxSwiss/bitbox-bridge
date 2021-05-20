# Package

1. install wix toolset and visual studio
2. install toml-echo: `cargo install --version 0.3.0 toml-echo`
3. launch X64 native tools command prompt for VS 20XX
4. run package-unsigned.cmd

# Signing

1. Modify the `signtool.cmd` to add the path to the certificate to the signtool.exe arguments
2. run package.cmd
