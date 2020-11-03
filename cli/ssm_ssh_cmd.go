package cli

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/mmmorris1975/ssm-session-client/ssmclient"
	"github.com/urfave/cli/v2"
	"strconv"
	"strings"
)

const ssmSshDesc = `Create an SSH over SSM session with the specified 'target_spec' using configuration from
   the given 'profile_name'.  The 'target_spec' is a colon-separated value of the target and an
   optional remote port number (ex. i-01234567:2222).  If no port is provided, the well-known
   SSH port is used.  The target string can be an EC2 instance ID, a tag key:value string which
   uniquely identifies an EC2 instance, the instance's private IPv4 address, or a DNS TXT record
   whose value is EC2 instance ID.

   This feature is meant to be used in SSH configuration files according to the AWS documentation
   at https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-getting-started-enable-ssh-connections.html
   except that the ProxyCommand syntax changes to:
     ProxyCommand sh -c "aws-runas ssm ssh profile_name %h:%p"
   Where profile_name is the AWS configuration profile to use (you should also be able to use the
   AWS_PROFILE environment variable, in which case the profile_name could be omitted), and %h:%p
   are standard SSH configuration substitutions for the host and port number to connect with, and
   can be left as-is`

var ssmSshCmd = &cli.Command{
	Name:        "ssh",
	Usage:       "Start an SSH over SSM session",
	ArgsUsage:   "profile_name target_spec",
	Description: ssmSshDesc,

	Flags: []cli.Flag{ssmUsePluginFlag},

	Action: func(ctx *cli.Context) error {
		target, c, err := doSsmSetup(ctx, 2)
		if err != nil {
			return err
		}

		// default ssh port if we're passed a target which doesn't explicitly set one
		port := "22"

		// "preprocess" target so it's acceptable to checkTarget()
		// Port number is expected to be the last element after splitting on ':' (except if using the
		// plain tag_key:tag_value format without a port), all other parts will be passed to checkTarget()
		parts := strings.Split(target, `:`)
		if len(parts) == 2 {
			// could be just tag_key:tag_value using default port, all other supported formats have
			// port as the final element.  If Atoi can convert the string to a number, assume it's
			// supposed to be a port, otherwise we'll use the default
			if _, err := strconv.Atoi(parts[1]); err == nil {
				target = parts[0]
				port = parts[1]
			}
		} else if len(parts) > 2 {
			// cases where port is expected to be the final element of the target specification
			target = strings.Join(parts[:len(parts)-1], `:`)
			port = parts[len(parts)-1]
		}

		ec2Id, err := ssmclient.ResolveTarget(target, c.ConfigProvider())
		if err != nil {
			return err
		}

		if ctx.Bool(ssmUsePluginFlag.Name) {
			params := map[string][]*string{
				"portNumber": {aws.String(port)},
			}

			in := &ssm.StartSessionInput{
				DocumentName: aws.String("AWS-StartSSHSession"),
				Parameters:   params,
				Target:       aws.String(ec2Id),
			}
			return execSsmPlugin(c.ConfigProvider(), in)
		}

		rpi, _ := strconv.Atoi(port)
		in := &ssmclient.PortForwardingInput{
			Target:     ec2Id,
			RemotePort: rpi,
		}
		return ssmclient.SshSession(c.ConfigProvider(), in)
	},
}
