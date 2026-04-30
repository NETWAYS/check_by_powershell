package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
)

const DefaultTimeout = 15 * time.Second

func TestConfig_Validate(t *testing.T) {
	c := &Config{}

	errVal := c.Validate()

	if errVal == nil {
		t.Error("Did expect error got nil")
	}

	// Most basic settings
	c.Host = "localhost"
	c.Command = "Get-Something"
	c.User = "administrator"
	c.Password = "verysecret"

	errVal = c.Validate()

	if errVal != nil {
		t.Error("Did not expect error got", errVal)
	}

	if c.Port != TlsPort {
		t.Error("Actual", c.Port, "Expected", TlsPort)
	}

	if c.NoTls != false {
		t.Error("Expected NoTls to be false, got true")
	}

	if c.AuthType != AuthDefault {
		t.Error("Actual", c.AuthType, "Expected", AuthDefault)
	}

	if c.validated != true {
		t.Error("Expected validated to be true, got false")
	}
}

func TestBuildConfigFlags(t *testing.T) {
	fs := &pflag.FlagSet{}
	config := BuildConfigFlags(fs)

	if fs.HasFlags() != true {
		t.Error("Expected hasFalgs to be true, got false")
	}

	if config.validated != false {
		t.Error("Expected config.validated to be false, got true")
	}

}

func TestConfig_BuildCommand(t *testing.T) {
	c := &Config{Command: "Get-Something"}

	cmd := c.BuildCommand()
	if !strings.Contains(c.BuildCommand(), "powershell.exe -EncodedCommand") {
		t.Error("\nExpected 'powershell.exe -EncodedCommand': ", cmd)
	}

	c = &Config{IcingaCommand: "Icinga-CheckSomething"}
	cmd = c.BuildCommand()
	if !strings.Contains(cmd, "powershell.exe -EncodedCommand") {
		t.Error("\nExpected 'powershell.exe -EncodedCommand': ", cmd)
	}
}

func TestConfig_Run_WithError(t *testing.T) {
	c := &Config{
		Host:     "192.0.2.11",
		User:     "admin",
		Password: "test",
		Command:  "Get-Host",
		NoTls:    true,
	}

	err := c.Validate()
	if err != nil {
		t.Error("Did not expect error got", err)
	}

	_, _, err = c.Run(1 * time.Second)
	if err == nil {
		t.Error("Did expect error got nil")
	}

	if !strings.Contains(err.Error(), "dial tcp 192.0.2.11:") {
		t.Error("\nExpected 'dial tcp 192.0.2.11:'", err.Error())
	}
}

func TestConfig_Run_Basic(t *testing.T) {
	if os.Getenv("WINRM_SKIP_BASIC") != "" {
		t.Skip("WINRM_SKIP_BASIC has been set")
	}

	if os.Getenv("WINRM_SKIP_UNENCRYPTED") != "" {
		t.Skip("WINRM_SKIP_UNENCRYPTED has been set")
	}

	c := buildEnvConfig(t, AuthBasic)
	c.NoTls = true

	fmt.Printf("%v\n", c)

	runCheck(t, c)
}

func TestConfig_Run_Basic_WithTLS(t *testing.T) {
	if os.Getenv("WINRM_SKIP_BASIC") != "" {
		t.Skip("WINRM_SKIP_BASIC has been set")
	}

	c := buildEnvConfig(t, AuthBasic)
	setupTlsFromEnv(t, c)

	err := c.Validate()
	if err != nil {
		t.Error("Did not expect error got", err)
	}

	fmt.Printf("%v\n", c)

	runCheck(t, c)
}

func TestConfig_Run_NTLM(t *testing.T) {
	if os.Getenv("WINRM_SKIP_UNENCRYPTED") != "" {
		t.Skip("WINRM_SKIP_UNENCRYPTED has been set")
	}

	c := buildEnvConfig(t, AuthNTLM)
	c.NoTls = true

	err := c.Validate()
	if err != nil {
		t.Error("Did not expect error got", err)
	}

	fmt.Printf("%v\n", c)

	runCheck(t, c)
}

func TestConfig_Run_NTLM_WithTls(t *testing.T) {
	c := buildEnvConfig(t, AuthNTLM)
	setupTlsFromEnv(t, c)

	err := c.Validate()
	if err != nil {
		t.Error("Did not expect error got", err)
	}

	fmt.Printf("%v\n", c)

	runCheck(t, c)
}

func TestConfig_Run_TLS(t *testing.T) {
	c := buildEnvConfig(t, AuthTLS)
	setupTlsFromEnv(t, c)

	if c.TlsCertPath == "" {
		t.Skip("WINRM_TLS_CERT not set")
	}

	err := c.Validate()
	if err != nil {
		t.Error("Did not expect error got", err)
	}

	fmt.Printf("%v\n", c)

	runCheck(t, c)
}

func runCheck(t *testing.T, c *Config) {
	err := c.Validate()
	if err != nil {
		t.Error("Did not expect error got", err)
	}

	rc, output, err := c.Run(DefaultTimeout)
	if err != nil {
		t.Error("Did not expect error got", err)
	}

	if 0 != rc {
		t.Error("Actual", rc, "Expected", 0)
	}

	if !strings.Contains(output, "ConsoleHost") {
		t.Error("\nExpected 'ConsoleHost'", output)
	}
}

func buildEnvConfig(t *testing.T, auth string) *Config {
	host := os.Getenv("WINRM_HOST")
	if host == "" {
		t.Skip("No env config for WINRM_*")
	}

	c := &Config{
		Host:     host,
		User:     os.Getenv("WINRM_USER"),
		Password: os.Getenv("WINRM_PASSWORD"),
		Command:  "Get-Host",
		AuthType: auth,
	}

	verb := strings.ToUpper(auth)

	if user := os.Getenv("WINRM_" + verb + "_USER"); user != "" {
		c.User = user
	}

	if password := os.Getenv("WINRM_" + verb + "_PASSWORD"); password != "" {
		c.Password = password
	}

	return c
}

func setupTlsFromEnv(t *testing.T, c *Config) {
	if os.Getenv("WINRM_SKIP_TLS") != "" {
		t.Skip("WINRM_SKIP_TLS has been set")
	}

	if os.Getenv("WINRM_INSECURE") != "" {
		c.Insecure = true
	}

	if file := os.Getenv("WINRM_TLS_CA"); file != "" {
		c.TlsCAPath = file
	}

	if file := os.Getenv("WINRM_TLS_CERT"); file != "" {
		c.TlsCertPath = file
	}

	if file := os.Getenv("WINRM_TLS_KEY"); file != "" {
		c.TlsKeyPath = file
	}

	if file := os.Getenv("WINRM_TLS_PORT"); file != "" {
		tmp, err := strconv.ParseInt(file, 10, 16)
		if err != nil {
			t.Error("Did not expect error got", err)
		}

		c.Port = int(tmp)
	}
}
