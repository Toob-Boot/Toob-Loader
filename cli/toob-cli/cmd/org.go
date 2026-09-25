package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
)

var orgCmd = &cobra.Command{
	Use:   "org",
	Short: "Manage the organizations you belong to",
	Long: `Lists, creates and leaves organizations, and invites people to them.

Organizations are managed by the Toob identity service; the registry says where it is.
Every command acts as the person signed in with 'toob login' — an API key does not reach them.`,
}

var orgListCmd = &cobra.Command{
	Use:   "list",
	Short: "List your organizations with your role and their plan",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		organizations, err := apiclient.New().Organizations(cmd_defaultCtx())
		if err != nil {
			return err
		}

		chosen, err := apiclient.ChosenOrganization()
		if err != nil {
			return err
		}

		ui.Header("Organizations")
		if len(organizations.Tenants) == 0 {
			ui.Muted("You belong to no organization yet. Create one with 'toob org create <name>'.")
		}
		for _, organization := range organizations.Tenants {
			name := organization.Name
			if chosen != nil && chosen.ID == organization.ID {
				name += " (in use)"
			}
			ui.KeyValue(name, fmt.Sprintf("%s · %s plan · %s", organization.Role, organization.Plan, ui.Gray(organization.ID)))
		}
		ui.Muted("%d of %d organizations created by you.", organizations.Created, organizations.CreateLimit)
		return nil
	},
}

var orgCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create an organization of your own",
	Long: `Creates an organization and makes you its owner. The name is lowercase letters, digits
and single hyphens. An account may create five; TOOB support sets up more.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		created, err := apiclient.New().CreateOrganization(cmd_defaultCtx(), args[0])
		if err != nil {
			return err
		}
		ui.Success("Created %s (%s). You are its owner.", ui.Bold(created.Name), created.ID)
		return nil
	},
}

var orgUseCmd = &cobra.Command{
	Use:   "use [organization]",
	Short: "Choose the organization your organization commands act on",
	Long: `Remembers an organization, by name or id, for the account signed in; commands that act on
an organization use it when none is named. --personal forgets it. Another account keeps its own.
It grants nothing: identity checks your membership on every request.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		personal, _ := cmd.Flags().GetBool("personal")
		switch {
		case personal && len(args) == 0:
			if err := apiclient.ClearOrganization(); err != nil {
				return err
			}
			ui.Success("No organization is in use; commands act on the one they name.")
			return nil
		case personal || len(args) == 0:
			return fmt.Errorf("name an organization, or pass --personal to forget the one in use")
		}

		organization, err := resolveOrganization(cmd_defaultCtx(), apiclient.New(), args[0])
		if err != nil {
			return err
		}
		if err := apiclient.ChooseOrganization(organization.ID, organization.Name); err != nil {
			return err
		}
		ui.Success("Organization commands now act on %s, where you are %s.", ui.Bold(organization.Name), organization.Role)
		return nil
	},
}

var orgCurrentCmd = &cobra.Command{
	Use:   "current",
	Short: "Show the organization your organization commands act on",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		chosen, err := apiclient.ChosenOrganization()
		if err != nil {
			return err
		}
		if chosen == nil {
			ui.Muted("None. Choose one with 'toob org use <organization>'.")
			return nil
		}
		ui.KeyValue(chosen.Name, ui.Gray(chosen.ID))
		return nil
	},
}

var orgInviteCmd = &cobra.Command{
	Use:   "invite [organization] <email>",
	Short: "Invite somebody by e-mail",
	Long: `Sends an invitation link to the address. It is accepted by an account whose verified
address this is, once, within 72 hours. The role is at most your own. Without an organization
named, the one --org names or 'toob org use' chose is the one invited to.`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		role, _ := cmd.Flags().GetString("role")
		client := apiclient.New()
		ctx := cmd_defaultCtx()

		organization, err := organizationOf(ctx, cmd, client, args[:len(args)-1])
		if err != nil {
			return err
		}
		invitation, err := client.Invite(ctx, organization.ID, args[len(args)-1], role)
		if err != nil {
			return err
		}
		ui.Success("Invited %s to %s as %s. The link is valid until %s.",
			invitation.Email, ui.Bold(organization.Name), invitation.Role, invitation.ExpiresAt)
		return nil
	},
}

var orgLeaveCmd = &cobra.Command{
	Use:   "leave [organization]",
	Short: "Leave an organization",
	Long:  `Leaves the organization named, or the one --org names or 'toob org use' chose.`,
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()
		ctx := cmd_defaultCtx()

		organization, err := organizationOf(ctx, cmd, client, args)
		if err != nil {
			return err
		}
		if err := client.LeaveOrganization(ctx, organization.ID); err != nil {
			return err
		}
		// An organization left is not the one in use any more.
		chosen, err := apiclient.ChosenOrganization()
		if err != nil {
			return err
		}
		if chosen != nil && chosen.ID == organization.ID {
			if err := apiclient.ClearOrganization(); err != nil {
				return err
			}
		}
		ui.Success("You left %s.", ui.Bold(organization.Name))
		return nil
	},
}

// organizationOf is the organization a command acts on: the one named, else --org, else the one
// 'toob org use' chose. The last is looked up like the others, so a membership that ended is
// reported rather than acted on.
func organizationOf(ctx context.Context, cmd *cobra.Command, client *apiclient.Client, named []string) (apiclient.Organization, error) {
	if len(named) == 1 {
		return resolveOrganization(ctx, client, named[0])
	}
	if flag, _ := cmd.Flags().GetString("org"); flag != "" {
		return resolveOrganization(ctx, client, flag)
	}
	chosen, err := apiclient.ChosenOrganization()
	if err != nil {
		return apiclient.Organization{}, err
	}
	if chosen == nil {
		return apiclient.Organization{}, fmt.Errorf("name an organization, pass --org, or choose one with 'toob org use <organization>'")
	}
	organization, err := resolveOrganization(ctx, client, chosen.ID)
	if err != nil {
		return apiclient.Organization{}, fmt.Errorf("the organization in use, %s, is not one of yours any more; choose another with 'toob org use': %w", chosen.Name, err)
	}
	return organization, nil
}

// resolveOrganization finds one of the person's organizations by id or by name.
func resolveOrganization(ctx context.Context, client *apiclient.Client, reference string) (apiclient.Organization, error) {
	organizations, err := client.Organizations(ctx)
	if err != nil {
		return apiclient.Organization{}, err
	}
	var named []apiclient.Organization
	for _, organization := range organizations.Tenants {
		if organization.ID == reference {
			return organization, nil
		}
		if strings.EqualFold(organization.Name, reference) {
			named = append(named, organization)
		}
	}
	switch len(named) {
	case 1:
		return named[0], nil
	case 0:
		return apiclient.Organization{}, fmt.Errorf("you belong to no organization %q; 'toob org list' shows yours", reference)
	default:
		return apiclient.Organization{}, fmt.Errorf("%d of your organizations are called %q; name one by its id ('toob org list')", len(named), reference)
	}
}

func init() {
	orgInviteCmd.Flags().String("role", "member", "The role the invitation grants: member, admin or owner")
	orgUseCmd.Flags().Bool("personal", false, "Forget the organization in use")
	orgCmd.PersistentFlags().String("org", "", "The organization to act on, by name or id, instead of the one in use")
	orgCmd.AddCommand(orgListCmd, orgCreateCmd, orgUseCmd, orgCurrentCmd, orgInviteCmd, orgLeaveCmd)
	rootCmd.AddCommand(orgCmd)
}
