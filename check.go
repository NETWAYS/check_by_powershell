package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/masterzen/winrm"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
)

const (
	Port        = 5985
	TlsPort     = 5986
	AuthDefault = AuthNTLM
	AuthBasic   = "basic"
	AuthNTLM    = "ntlm"
	AuthSSH     = "ssh"
	AuthTLS     = "tls"
)

type Config struct {
	Host          string
	Port          int
	User          string
	Password      string
	NoTls         bool
	Insecure      bool
	TlsCAPath     string
	tlsCA         []byte
	TlsCertPath   string
	tlsCert       []byte
	TlsKeyPath    string
	tlsKey        []byte
	Command       string
	IcingaCommand string
	AuthType      string
	SSHHost       string
	SSHUser       string
	SSHPassword   string
	validated     bool
}

func BuildConfigFlags(fs *pflag.FlagSet) (config *Config) {
	config = &Config{}

	fs.StringVarP(&config.Host, "host", "H", "127.0.0.1",
		"Host name, IP Address of the remote host")
	fs.IntVarP(&config.Port, "port", "p", 0, "Port number WinRM") // TODO: document default

	fs.StringVarP(&config.User, "user", "U", "", "Username of the remote host")
	fs.StringVarP(&config.Password, "password", "P", "", "Password of the user")

	fs.BoolVarP(&config.Insecure, "insecure", "k", false,
		"Don't verify the hostname on the returned certificate")
	fs.BoolVar(&config.NoTls, "no-tls", false, "Don't use a TLS connection, use the HTTP protocol")
	fs.StringVar(&config.TlsCAPath, "ca", "", "CA certificate")
	fs.StringVar(&config.TlsCertPath, "cert", "", "Client certificate")
	fs.StringVar(&config.TlsKeyPath, "key", "", "Client Key")

	fs.StringVar(&config.Command, "cmd", "", "Command to execute on the remote machine")
	fs.StringVar(&config.IcingaCommand, "icingacmd", "",
		"Executes commands of Icinga PowerShell Framework (e.g. Invoke-IcingaCheckCPU)")

	fs.StringVar(&config.AuthType, "auth", AuthDefault, "Authentication mechanism - Basic, NTLM, TLS, SSH")

	// AuthSSH
	fs.StringVar(&config.SSHHost, "sshhost", "", "SSH Host (mandatory if --auth=SSH)")
	fs.StringVar(&config.SSHUser, "sshuser", "", "SSH Username (mandatory if --auth=SSH)")
	fs.StringVar(&config.SSHPassword, "sshpassword", "", "SSH Password (mandatory if --auth=SSH)")

	// Compat flags
	// TODO: remove?
	fs.BoolVarP(&config.Insecure, "unsecure", "u", false,
		"Don't verify the hostname on the returned certificate")

	_ = fs.MarkHidden("unsecure")

	return
}

// Validate ensures the configuration is valid, and will set and evaluate some settings
func (c *Config) Validate() (err error) {
	c.validated = false

	if c.Host == "" {
		return errors.New("host must be configured")
	}

	// Any commands?
	if c.Command == "" && c.IcingaCommand == "" {
		return errors.New("no command specified")
	} else if c.Command != "" && c.IcingaCommand != "" {
		return errors.New("you can only use command OR icingacommand")
	}

	// Set default port if unset
	if c.Port < 1 {
		c.Port = TlsPort
		if c.NoTls {
			c.Port = Port
		}
	}

	if c.TlsCertPath != "" {
		c.tlsCert, err = os.ReadFile(c.TlsCertPath)
		if err != nil {
			return fmt.Errorf("could not read certificate: %w", err)
		}

		if c.TlsKeyPath == "" {
			return errors.New("please specify certificate key when tls is enabled")
		}

		c.tlsKey, err = os.ReadFile(c.TlsKeyPath)
		if err != nil {
			return fmt.Errorf("could not read certificate key: %w", err)
		}

		if c.AuthType == "" {
			c.AuthType = AuthTLS
		} else {
			slog.Warn(fmt.Sprintf("auth type is %s, but TLS certificates are supplied", c.AuthType))
		}
	}

	if c.TlsCAPath != "" {
		c.tlsCA, err = os.ReadFile(c.TlsCAPath)
		if err != nil {
			return fmt.Errorf("could not read CA file: %w", err)
		}
	}

	// AuthType
	if c.AuthType == "" {
		c.AuthType = AuthDefault
	}

	auth := strings.ToLower(c.AuthType)
	switch auth {
	case AuthBasic, AuthNTLM:
		if c.User == "" || c.Password == "" {
			return errors.New("user and password must be configured")
		}
	case AuthTLS:
	case AuthSSH:
		if c.SSHHost == "" || c.SSHUser == "" || c.SSHPassword == "" {
			return fmt.Errorf("please specify host, user and port for auth type: %s", c.AuthType)
		}
	default:
		return fmt.Errorf("invalid auth type specified: %s", c.AuthType)
	}
	// store the lower case variant for later
	c.AuthType = auth

	// Validation complete
	c.validated = true

	return nil
}

func (c *Config) BuildCommand() (cmd string) {
	var wrap string
	if c.IcingaCommand != "" {
		wrap = "try { Use-Icinga; exit (%s) } catch { Write-Host ('UNKNOWN: ' + $error); exit 3 }"
		cmd = fmt.Sprintf(wrap, c.IcingaCommand)
	} else {
		wrap = "try { %s; exit $LASTEXITCODE } catch { Write-Host ('UNKNOWN: ' + $error); exit 3 }"
		cmd = fmt.Sprintf(wrap, c.Command)
	}

	slog.Debug("prepared pwsh for execution", "cmd", cmd)

	cmd = winrm.Powershell(cmd)

	slog.Debug("prepared winrm command for execution", "cmd", cmd)

	return
}

func (c *Config) Run(timeout time.Duration) (rc int, output string, err error) {
	if !c.validated {
		panic("you need to call Validate() before Run()")
	}

	endpoint := winrm.NewEndpoint(
		c.Host,     // Host to connect to
		c.Port,     // Winrm port
		!c.NoTls,   // Use TLS
		c.Insecure, // Allow insecure connection
		c.tlsCA,    // CA certificate
		c.tlsCert,  // Client Certificate
		c.tlsKey,   // Client Key
		timeout,    // Timeout
	)
	params := winrm.DefaultParameters

	// prepare auth parameters
	switch c.AuthType {
	case AuthNTLM:
		params.TransportDecorator = func() winrm.Transporter {
			return &winrm.ClientNTLM{}
		}
	case AuthTLS:
		params.TransportDecorator = func() winrm.Transporter {
			return &winrm.ClientAuthRequest{}
		}
	case AuthSSH:
		// TODO: port configuration?
		var sshClient *ssh.Client
		sshClient, err = ssh.Dial("tcp", c.SSHHost+":22", &ssh.ClientConfig{
			User:            c.SSHUser,
			Auth:            []ssh.AuthMethod{ssh.Password(c.SSHPassword)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // TODO: really?
		})

		if err != nil {
			err = fmt.Errorf("could not connect via SSH: %w", err)
			return
		}

		params.Dial = sshClient.Dial
	default: // default is AuthBasic
		params.TransportDecorator = nil
	}

	// prepare client
	client, err := winrm.NewClientWithParameters(endpoint, c.User, c.Password, params)
	if err != nil {
		err = fmt.Errorf("could not create client: %w", err)
		return
	}

	// execute the check remotely
	var (
		stdout = &bytes.Buffer{}
		stderr = &bytes.Buffer{}
	)

	ctx := context.Background()

	rc, err = client.RunWithContext(ctx, c.BuildCommand(), stdout, stderr)
	if err != nil {
		err = fmt.Errorf("execution of remote cmd failed: %w", err)
		return
	}

	output = stdout.String()

	return
}
