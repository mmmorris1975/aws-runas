/*
 * Copyright (c) 2021 Michael Morris. All Rights Reserved.
 *
 * Licensed under the MIT license (the "License"). You may not use this file except in compliance
 * with the License. A copy of the License is located at
 *
 * https://github.com/mmmorris1975/aws-runas/blob/master/LICENSE
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under the License.
 */

package cli

import (
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/kevinburke/ssh_config"
	"github.com/mmmorris1975/ssm-session-client/ssmclient"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
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
  ProxyCommand aws-runas ssm ssh [--ec2ic] profile_name %r@%h:%p
Where profile_name is the AWS configuration profile to use (you should also be able to use the
AWS_PROFILE environment variable, in which case the profile_name could be omitted), and %r@%h:%p
are standard SSH configuration substitutions for the remote user name, host and port number to connect with,
and can be left as-is.  If the optional --ec2ic argument is supplied, the public key is provisioned on the
remote system using EC2 Instance Connect during the SSH session setup.`

var ec2InstanceConnectFlag = &cli.BoolFlag{
	Name:  "ec2ic",
	Usage: "Send public key to instance using EC2 Instance Connect",
}

var ssmSshCmd = &cli.Command{
	Name:         "ssh",
	Usage:        "Start an SSH over SSM session",
	ArgsUsage:    "profile_name target_spec",
	Description:  ssmSshDesc,
	BashComplete: bashCompleteProfile,

	Flags: []cli.Flag{ec2InstanceConnectFlag, ssmUsePluginFlag},

	Action: func(ctx *cli.Context) error {
		target, c, err := doSsmSetup(ctx, 2)
		if err != nil {
			return err
		}

		user, host, port := parseTargetSpec(target)

		ec2Id, err := ssmclient.ResolveTarget(host, c.ConfigProvider())
		if err != nil {
			return err
		}

		if ctx.Bool(ec2InstanceConnectFlag.Name) {
			var pubKey string
			if pubKey, err = getPubKey(host); err != nil {
				return err
			}

			ec2ic := ec2instanceconnect.NewFromConfig(c.ConfigProvider())
			pubkeyIn := &ec2instanceconnect.SendSSHPublicKeyInput{
				InstanceId:     &ec2Id,
				InstanceOSUser: &user,
				SSHPublicKey:   &pubKey,
			}

			if _, err = ec2ic.SendSSHPublicKey(ctx.Context, pubkeyIn); err != nil {
				return err
			}
		}

		if ctx.Bool(ssmUsePluginFlag.Name) {
			params := map[string][]string{
				"portNumber": {port},
			}

			in := &ssm.StartSessionInput{
				DocumentName: aws.String("AWS-StartSSHSession"),
				Parameters:   params,
				Target:       &ec2Id,
			}
			return execSsmPlugin(c.ConfigProvider(), in)
		}

		rpi, _ := strconv.Atoi(port)
		in := &ssmclient.PortForwardingInput{
			Target:     ec2Id,
			RemotePort: rpi,
		}
		return ssmclient.SSHSession(c.ConfigProvider(), in)
	},
}

func parseTargetSpec(target string) (string, string, string) {
	var user = "ec2-user"
	var port = "22"
	var host string

	userHostPart := strings.Split(target, `@`)
	if len(userHostPart) > 1 {
		user = userHostPart[0]
		userHostPart = userHostPart[1:]
	}

	// Format could be host:port or possibly tag_key:tag_value:port
	hostPortPart := strings.Split(userHostPart[0], `:`)
	if len(hostPortPart) == 1 {
		// bare host, use default port
		host = hostPortPart[0]
	} else {
		// Could be host:port, tag_key:tag_value with default port, or tag_key:tag_value:port
		// Use Atoi to see if the last element is a numeric string and assume that's a port number
		if i, err := strconv.Atoi(hostPortPart[len(hostPortPart)-1]); err == nil && i <= 65535 {
			host = strings.Join(hostPortPart[:len(hostPortPart)-1], `:`)
			port = hostPortPart[len(hostPortPart)-1]
		} else {
			host = strings.Join(hostPortPart, `:`)
		}
	}

	return user, host, port
}

func getPubKey(host string) (string, error) {
	var err error

	for _, key := range ssh_config.GetAll(host, "IdentityFile") {
		if strings.HasPrefix(key, "~/") {
			dirname, _ := os.UserHomeDir()
			key = filepath.Join(dirname, key[2:])
		}

		var bytes []byte
		bytes, err = os.ReadFile(key)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", err
		}

		var signer ssh.Signer
		signer, err = ssh.ParsePrivateKey(bytes)
		if err != nil {
			var protectedKeyErr *ssh.PassphraseMissingError
			if errors.As(err, &protectedKeyErr) {
				// FIXME handle a passphrase protected key ...
				//   for now, just continue an hope there's an "unprotected" key in the list to try
				continue
			}
			return "", err
		}

		return string(ssh.MarshalAuthorizedKey(signer.PublicKey())), nil
	}

	return "", errors.New("public key not available")
}
