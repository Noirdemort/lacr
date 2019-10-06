#!/bin/bash
pip install $(cat requirements.txt)
if [[ "$OSTYPE" == "linux-gnu" ]]; then
        # Linux
        sudo apt-get install libssl-dev
elif [[ "$OSTYPE" == "darwin"* ]]; then
        # Mac OSX
        /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
        brew install openssl
elif [[ "$OSTYPE" == "cygwin" ]]; then
        # POSIX compatibility layer and Linux environment emulation for Windows
#        Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        choco install openssl
elif [[ "$OSTYPE" == "msys" ]]; then
        # Lightweight shell and GNU utilities compiled for Windows (part of MinGW)
#        Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        choco install openssl
elif [[ "$OSTYPE" == "win32" ]]; then
        # I'm not sure this can happen.
#        Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        choco install openssl
elif [[ "$OSTYPE" == "freebsd"* ]]; then
        # ...
        echo "Install Python 3.4 or later. Also add openssl to PATH."
else
        echo "Install Python 3.4 or later. Also add openssl to PATH."
        # Unknown.
fi
