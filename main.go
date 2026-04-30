package main

import (
	"fmt"
	"os"
	"time"

	"github.com/NETWAYS/go-check"
)

const readme = `Icinga check plugin to run checks and other commands directly on
any Windows system using WinRM (Windows Remote Management) and Powershell

Main use case would be to call one of the plugins from the Icinga Powershell Framework.
This will avoid the requirement of installing an Icinga 2 agent on every Windows system.

The plugin will require WinRM to be preconfigured for access with a HTTPs or HTTP connection.

Supported authentication methods:

* Basic with local users
* NTLM with local or AD accounts
* TLS client certificate

https://github.com/Netways/check_by_powershell

Copyright (c) 2026 Netways GmbH <info@netways.de>
Copyright (c) 2020-2026 Icinga GmbH <info@icinga.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.`

func main() {
	defer check.CatchPanic()

	plugin := check.NewConfig()

	plugin.Name = "check_by_powershell"
	plugin.Readme = readme
	plugin.Version = buildVersion()
	plugin.Timeout = 10

	config := BuildConfigFlags(plugin.FlagSet)
	plugin.ParseArguments()

	err := config.Validate()
	if err != nil {
		check.ExitRaw(check.Unknown, "could not validate parameters: "+err.Error())
	}

	rc, output, err := config.Run(time.Duration(plugin.Timeout) * time.Second)
	if err != nil {
		check.ExitRaw(check.Unknown, "execution failed: "+err.Error())
	}

	fmt.Print(output)
	os.Exit(rc)
}
