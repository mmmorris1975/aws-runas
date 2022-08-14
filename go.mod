module github.com/mmmorris1975/aws-runas

go 1.16

require (
	github.com/PuerkitoBio/goquery v1.8.0
	github.com/aws/aws-sdk-go-v2 v1.16.11
	github.com/aws/aws-sdk-go-v2/config v1.16.1
	github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect v1.14.4
	github.com/aws/aws-sdk-go-v2/service/ecr v1.17.12
	github.com/aws/aws-sdk-go-v2/service/iam v1.18.13
	github.com/aws/aws-sdk-go-v2/service/ssm v1.27.9
	github.com/aws/aws-sdk-go-v2/service/sts v1.16.13
	github.com/aws/smithy-go v1.12.1
	github.com/dustin/go-humanize v1.0.1-0.20210705192016-249ff6c91207
	github.com/kevinburke/ssh_config v1.2.0
	github.com/mmmorris1975/simple-logger v0.5.1
	github.com/mmmorris1975/ssm-session-client v0.300.0
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635
	github.com/urfave/cli/v2 v2.3.1-0.20211106113742-12b7dfd08cb0
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa
	golang.org/x/net v0.0.0-20220812174116-3211cb980234
	golang.org/x/sys v0.0.0-20220811171246-fbc7d0a398ab
	golang.org/x/term v0.0.0-20220722155259-a9ba230a4035
	gopkg.in/ini.v1 v1.66.2
)

// REF: https://github.com/aws/session-manager-plugin/issues/1
replace github.com/aws/SSMCLI => github.com/aws/session-manager-plugin v0.0.0-20220617200849-916aa5c1c241
