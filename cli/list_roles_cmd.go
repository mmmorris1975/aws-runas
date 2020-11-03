package cli

import (
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/urfave/cli/v2"
	"sort"
	"strings"
)

var rolesCmd = &cli.Command{
	Name:      "roles",
	Usage:     rolesFlag.Usage,
	ArgsUsage: "[profile_name]",

	BashComplete: bashCompleteProfile,

	Action: func(ctx *cli.Context) error {
		_, cfg, err := resolveConfig(ctx, 1)
		if err != nil {
			return err
		}

		if arn.IsARN(cfg.ProfileName) {
			return errors.New("profile looks like an ARN, check command parameters and environment variables")
		}

		if len(cfg.WebIdentityUrl) > 0 {
			return errors.New("detected Web Identity profile, only IAM and SAML profiles support role enumeration")
		}

		c, err := clientFactory.Get(cfg)
		if err != nil {
			return err
		}

		id, err := c.Identity()
		if err != nil {
			return err
		}

		roles, err := c.Roles()
		if err != nil {
			return err
		}
		sort.Strings(*roles)

		fmt.Printf("Available role ARNs for %s\n", id.Username)
		for _, r := range *roles {
			// filter out wildcards roles, since they can't be used in config files
			if strings.Contains(r, "*") {
				continue
			}
			fmt.Println("  " + r)
		}

		return nil
	},
}
