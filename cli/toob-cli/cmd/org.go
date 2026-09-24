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

		ui.Header("Organizations")
		if len(organizations.Tenants) == 0 {
			ui.Muted("You belong to no organization yet. Create one with 'toob org create <name>'.")
		}
		for _, organization := range organizations.Tenants {
			ui.KeyValue(organization.Name, fmt.Sprintf("%s · %s plan · %s", organization.Role, organization.Plan, ui.Gray(organization.ID)))
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

var orgInviteCmd = &cobra.Command{
	Use:   "invite <organization> <email>",
	Short: "Invite somebody by e-mail",
	Long: `Sends an invitation link to the address. It is accepted by an account whose verified
address this is, once, within 72 hours. The role is at most your own.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		role, _ := cmd.Flags().GetString("role")
		client := apiclient.New()
		ctx := cmd_defaultCtx()

		organization, err := resolveOrganization(ctx, client, args[0])
		if err != nil {
			return err
		}
		invitation, err := client.Invite(ctx, organization.ID, args[1], role)
		if err != nil {
			return err
		}
		ui.Success("Invited %s to %s as %s. The link is valid until %s.",
			invitation.Email, ui.Bold(organization.Name), invitation.Role, invitation.ExpiresAt)
		return nil
	},
}

var orgLeaveCmd = &cobra.Command{
	Use:   "leave <organization>",
	Short: "Leave an organization",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()
		ctx := cmd_defaultCtx()

		organization, err := resolveOrganization(ctx, client, args[0])
		if err != nil {
			return err
		}
		if err := client.LeaveOrganization(ctx, organization.ID); err != nil {
			return err
		}
		ui.Success("You left %s.", ui.Bold(organization.Name))
		return nil
	},
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
	orgCmd.AddCommand(orgListCmd, orgCreateCmd, orgInviteCmd, orgLeaveCmd)
	rootCmd.AddCommand(orgCmd)
}
