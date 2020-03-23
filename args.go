package main

import (
	"github.com/alecthomas/kingpin"
	"net/url"
	"os"
	"time"
)

var (
	updateFlag   *bool
	diagFlag     *bool
	listRoles    *bool
	listMfa      *bool
	ec2MdFlag    *bool
	verbose      *bool
	envFlag      *bool
	showExpire   *bool
	refresh      *bool
	sesCreds     *bool
	whoAmI       *bool
	duration     *time.Duration
	roleDuration *time.Duration
	mfaCode      *string
	mfaSerial    *string
	extnId       *string
	jumpArn      *string
	samlUrl      **url.URL
	samlUser     *string
	samlPass     *string
	samlProvider *string
	outputFmt    *string

	exe    *kingpin.CmdClause
	shell  *kingpin.CmdClause
	fwd    *kingpin.CmdClause
	passwd *kingpin.CmdClause

	execArgs  = new(cmdArgs)
	shellArgs = new(cmdArgs)
	fwdArgs   = new(cmdArgs)
	pwdArgs   = new(cmdArgs)
)

type cmdArgs struct {
	profile   *string
	cmd       *[]string
	target    *string
	localPort *uint16
}

func init() {
	const (
		cmdDesc             = "Create an environment for interacting with the AWS API using an assumed role"
		updateArgDesc       = "Check for updates to aws-runas"
		diagArgDesc         = "Run diagnostics to gather info to troubleshoot issues"
		listRoleArgDesc     = "List role ARNs you are able to assume"
		listMfaArgDesc      = "List the ARN of the MFA device associated with your IAM account"
		ec2ArgDesc          = "Run a mock EC2 metadata service to provide role credentials"
		verboseArgDesc      = "Print verbose/debug messages"
		envArgDesc          = "Pass credentials to program as environment variables"
		showExpArgDesc      = "Show credential expiration time"
		refreshArgDesc      = "Force a refresh of the cached credentials"
		sesCredArgDesc      = "Print eval()-able session token info, or run command using session token credentials"
		durationArgDesc     = "Duration of the retrieved session token"
		roleDurationArgDesc = "Duration of the assume role credentials"
		mfaCodeDesc         = "MFA token code"
		mfaSerialDesc       = "Serial number (or AWS ARN) of MFA device needed to perform Assume Role operation"
		extnIdDesc          = "External ID to use to Assume the Role"
		jumpArnDesc         = "ARN of the 'jump role' to use with SAML integration"
		samlUrlDesc         = "URL of the SAML authentication endpoint"
		samlUserDesc        = "Username for SAML authentication"
		samlPassDesc        = "Password for SAML authentication"
		samlProviderDesc    = "The name of the saml provider to use, and bypass auto-detection"
		profileArgDesc      = "name of profile, or role ARN"
		fwdPortDesc         = "The local port for the forwarded connection"
		outputArgDesc       = "Credential output format, valid values: env (default) or json"
		whoAmIArgDesc       = "Print the AWS identity information for the provided profile"
	)

	// special flags
	ec2MdFlag = kingpin.Flag("ec2", ec2ArgDesc).Bool()
	verbose = kingpin.Flag("verbose", verboseArgDesc).Short('v').Envar("RUNAS_VERBOSE").Bool()
	envFlag = kingpin.Flag("env", envArgDesc).Short('E').Envar("RUNAS_ENV_CREDENTIALS").Bool()
	showExpire = kingpin.Flag("expiration", showExpArgDesc).Short('e').Bool()
	outputFmt = kingpin.Flag("output", outputArgDesc).Short('O').Envar("RUNAS_OUTPUT_FORMAT").Default("env").Enum("env", "json")
	whoAmI = kingpin.Flag("whoami", whoAmIArgDesc).Short('w').Bool()

	// flags which don't actually do any credential stuff
	updateFlag = kingpin.Flag("update", updateArgDesc).Short('u').Bool()
	diagFlag = kingpin.Flag("diagnose", diagArgDesc).Short('D').Bool()
	listRoles = kingpin.Flag("list-roles", listRoleArgDesc).Short('l').Bool()
	listMfa = kingpin.Flag("list-mfa", listMfaArgDesc).Short('m').Bool() // only relevant for non-SAML profiles

	// flags which affect the configuration used for fetching credentials of any flavor
	refresh = kingpin.Flag("refresh", refreshArgDesc).Short('r').Bool()
	sesCreds = kingpin.Flag("session", sesCredArgDesc).Short('s').Envar("RUNAS_SESSION_CREDENTIALS").Bool()
	duration = kingpin.Flag("duration", durationArgDesc).Short('d').Envar("SESSION_TOKEN_DURATION").Duration()
	roleDuration = kingpin.Flag("role-duration", roleDurationArgDesc).Short('a').Envar("CREDENTIALS_DURATION").Duration()
	mfaCode = kingpin.Flag("otp", mfaCodeDesc).Short('o').Envar("MFA_CODE").String() // valid for SAML and non-SAML profiles

	// flags which are only valid for non-SAML profiles
	mfaSerial = kingpin.Flag("mfa-serial", mfaSerialDesc).Short('M').Envar("MFA_SERIAL").String()
	extnId = kingpin.Flag("external-id", extnIdDesc).Short('X').Envar("EXTERNAL_ID").String()

	// flags which are only valid for SAML profiles
	jumpArn = kingpin.Flag("jump-role", jumpArnDesc).Short('J').Envar("JUMP_ROLE_ARN").String()
	samlUrl = kingpin.Flag("saml-url", samlUrlDesc).Short('S').Envar("SAML_AUTH_URL").URL()
	samlUser = kingpin.Flag("saml-user", samlUserDesc).Short('U').Envar("SAML_USERNAME").String()
	samlPass = kingpin.Flag("saml-password", samlPassDesc).Short('P').Envar("SAML_PASSWORD").String()
	samlProvider = kingpin.Flag("saml-provider", samlProviderDesc).Short('R').Envar("SAML_PROVIDER").String()

	// Can not use Command() if you also have top-level Arg()s defined, so wrap "typical" behavior
	// as the default command so users can continue to use the tool as before
	exe = kingpin.Command("exec", cmdDesc).Default().Hidden() // to hide or not to hide, that is the question
	execArgs.profile = profileEnvArg(exe, profileArgDesc)
	execArgs.cmd = exe.Arg("cmd", "command to execute using configured profile").Strings()

	shell = kingpin.Command("shell", "Start an SSM shell session to the given target")
	shellArgs.profile = profileEnvArg(shell, profileArgDesc)
	shellArgs.target = shell.Arg("target", "The EC2 instance to connect via SSM").String()

	fwd = kingpin.Command("forward", "Start an SSM port-forwarding session to the given target").Alias("fwd")
	fwdArgs.localPort = fwd.Flag("port", fwdPortDesc).Short('p').Default("0").Uint16()
	fwdArgs.profile = profileEnvArg(fwd, profileArgDesc)
	fwdArgs.target = fwd.Arg("target", "The EC2 instance id and remote port, separated by ':'").String()

	passwd = kingpin.Command("password", "Set the SAML password for the specified profile").Alias("pwd")
	pwdArgs.profile = profileEnvArg(passwd, profileArgDesc)

	kingpin.Version(Version)
	kingpin.CommandLine.VersionFlag.Short('V')
	kingpin.CommandLine.HelpFlag.Short('h')
	kingpin.CommandLine.Help = cmdDesc
	kingpin.CommandLine.Interspersed(false)
}

// Since the profile name to use can be set as an environment variable, or passed in as the 1st arg in the command,
// we can't simply do cmd.Arg("profile", ...).Envvar("AWS_PROFILE").String(), because if we set the env var, and specify
// a command, kingpin assumes that the 1st element of the command will be the profile name, and not part of the command.
// This feels a bit clumsy, but does work around that situation.
func profileEnvArg(cmd *kingpin.CmdClause, desc string) *string {
	if v := os.Getenv("AWS_PROFILE"); len(v) > 0 {
		return &v
	}
	return cmd.Arg("profile", desc).String()
}
