# check_by_powershell

<!-- NOTE: Update this description also in main.go -->

Icinga check plugin to run checks and other commands directly on any Windows system using
WinRM (Windows Remote Management) and Powershell.

Main use case would be to call one of the [plugins](https://github.com/Icinga/icinga-powershell-plugins)
from the [Icinga Powershell Framework](https://github.com/Icinga/icinga-powershell-framework). This will avoid the
requirement of installing an Icinga 2 agent on every Windows system.

The plugin will require WinRM to be preconfigured for access with a HTTPs or HTTP connection.

Supported authentication methods:

* Basic with local users
* NTLM with local or AD accounts
* TLS client certificate
* (SSH connection)

Not supported at the moment is Kerberos.

## Usage

```
Arguments:
  -H, --host string          Host name, IP Address of the remote host (default "127.0.0.1")
  -p, --port int             Port number WinRM
  -U, --user string          Username of the remote host
  -P, --password string      Password of the user
  -k, --insecure             Don't verify the hostname on the returned certificate
      --no-tls               Don't use a TLS connection, use the HTTP protocol
      --ca string            CA certificate
      --cert string          Client certificate
      --key string           Client Key
      --cmd string           Command to execute on the remote machine
      --icingacmd string     Executes commands of Icinga PowerShell Framework (e.g. Invoke-IcingaCheckCPU)
      --auth string          Authentication mechanism - NTLM | SSH (default "basic")
      --sshhost string       SSH Host (mandatory if --auth=SSH)
      --sshuser string       SSH Username (mandatory if --auth=SSH)
      --sshpassword string   SSH Password (mandatory if --auth=SSH)
  -t, --timeout int          Abort the check after n seconds (default 10)
  -d, --debug                Enable debug mode
  -v, --verbose              Enable verbose mode
  -V, --version              Print version and exit
```

Also, see the Icinga 2 examples in the [icinga2/ directory](icinga2/).

## Examples

Calling a PowerShell plugin from the framework is easy:

    ./check_by_powershell  -H example.local.de --user 'ad\user' --password '!secret!pw' \
      --icingacmd 'Invoke-IcingaCheckCPU -Warning 80 -Critical 90'

    [OK] Check package "CPU Load"
    | 'core_23_10'=2.31%;;;0;100 'core_23_3'=2.54%;;;0;100 'core_23_15'=2.12%;;;0;100 'core_23_5'=2.39%;;;0;100
      'core_23_1'=2.04%;;;0;100 'core_23'=1.93%;;;0;100 'core_2_15'=2.78%;;;0;100 'core_2_10'=2.89%;;;0;100 [...]

Notes:
* You can use `--insecure` to skip CA trust and certificate checks - be careful!
* You can use `--no-tls` to use a HTTP connection

Executing any other Windows program or script, could be another Icinga plugin:

    ./check_by_powershell -H 192.168.172.217 \
      --user 'windowsuser' --password 'secret!pw' \
      --cmd "cscript.exe /T:30 /NoLogo C:\Windows\system32\check_time.vbs 1.de.pool.ntp.org 20 240"

    OK - NTP OK: Offset +0.0556797 secs|'offset'=+0.0556797s;20;240;

If you run a program or script like this, you need to make sure to exit the script with a proper exit code, to reflect
the correct status for Icinga.

## Preparing the Windows machine

By default, WinRM is not enabled, and if enabled, will only allow Kerberos authentication. WinRM can be configured in
many ways, to allow connections by HTTP or HTTPs.

Best practice would be to configure WinRM with a TLS certificate, signed by the PKI of the Active Directory domain,
and using NTLM auth to access the systems.

Anything you configure via cmd or powershell needs to be run from an administrative shell.

We start with the minimal setup of enabling WinRM and raising the memory limit:

```
winrm quickconfig
winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="1024"}'
```

### Setting up a HTTPS / TLS listener

Make sure to install the certificate in the local machine cert store. This example is using PowerShell.

WinRM HTTPS requires a local computer "Server Authentication" certificate with a CN matching the hostname, that is not
expired, revoked, or self-signed to be installed.

```powershell
# Find the cert
Get-ChildItem -Path cert:\LocalMachine\My -Recurse;

# Put the thumbprint here or script it otherwise
$CertThumbprint = 'cert_thumbprint';

# Allow PS-Remote configuration
Enable-PSRemoting -SkipNetworkProfileCheck -Force;

# (optional) Disable HTTP transport for PS-Remoting to ensure encryption
Get-ChildItem WSMan:\Localhost\listener | Where-Object Keys -eq "Transport=HTTP" | Remove-Item -Recurse;

# Set the HTTPS Transport with our provided Thumbprint for the SSL certificate
New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $CertThumbprint -Force;

# Set Firewall Rule for allowing communication
New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" `
  -Name "Windows Remote Management (HTTPS-In)" -Profile Any -LocalPort 5986 -Protocol TCP;

# Enable the HTTPS listener
Set-Item WSMan:\localhost\Service\EnableCompatibilityHttpsListener -Value true;

# Disable possible old HTTP firewall rules (names language specific)
Disable-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)";
Disable-NetFirewallRule -DisplayName "Windows-Remoteverwaltung (HTTP eingehend)";

# (optional) You can configure hosts that are allowed to connect to WinRM
winrm set winrm/config/client '@{TrustedHosts="*"}';

Restart-Service winrm;
```

If it's necessary to use a self-signed-certificate, you can follow the
[guide on visualstudiogeeks.com](https://www.visualstudiogeeks.com/devops/how-to-configure-winrm-for-https-manually).

### Enabling Basic Auth

Basic auth can be used as fallback for NTLM, but will require a local account on each machine.

```
winrm set winrm/config/service/Auth '@{Basic="true"}'
```

### Enabling unencrypted HTTP or basic auth

**Warning:** This is insecure, and should only be done during testing!

This will allow credentials and data transmitted over an **unencrypted** connection like HTTP.

```
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
```

## Manually building the program

The plugin is written in Golang and can easily be compiled from source, see the [documentation](https://golang.org/doc/)
for further details.

```
GOOS=linux GOARCH=amd64 go build -o check_by_powershell .
GOOS=windows GOARCH=amd64 go build -o check_by_powershell.exe .
```

## Acknowledgements

To Brice Figureau [@masterzen](https://github.com/masterzen), who built a
[WinRM client for golang](https://github.com/masterzen/winrm).

## License

Copyright (c) 2026 [Netways GmbH](mailto:info@netways.de)
Copyright (c) 2020-2026 [Icinga GmbH](mailto:info@icinga.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see [gnu.org/licenses](https://www.gnu.org/licenses/).
