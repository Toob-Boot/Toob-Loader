package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
)

func newOrgCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "org",
		Short: "Manage Toob Registry organizations and package namespaces",
	}

	c.AddCommand(
		newOrgListCmd(),
		newOrgCreateCmd(),
		newOrgUseCmd(),
		newOrgInviteCmd(),
		newOrgAcceptInviteCmd(),
		newOrgLeaveCmd(),
		newOrgNamespaceCmd(),
	)
	return c
}

func newOrgListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List organizations you belong to",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := commandContext(cmd, defaultCmdTimeout)
			defer cancel()

			client := apiclient.New()
			orgs, err := client.Organizations(ctx)
			if err != nil {
				return fmt.Errorf("list organizations: %w", err)
			}

			chosen, _ := apiclient.ChosenOrganization()
			if orgs == nil || len(orgs.Tenants) == 0 {
				ui.Info("You do not belong to any organizations.")
				return nil
			}

			for _, org := range orgs.Tenants {
				marker := " "
				if chosen != nil && (org.ID == chosen.ID || strings.EqualFold(org.Name, chosen.Name)) {
					marker = "*"
				}
				ui.Info("%s %-12s %-24s (role=%s, plan=%s)",
					marker,
					shortID(sanitizeDisplay(org.ID), 12),
					sanitizeDisplay(org.Name),
					sanitizeDisplay(org.Role),
					sanitizeDisplay(org.Plan))
			}
			return nil
		},
	}
}

func newOrgCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new organization and reserve its default package namespace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			if name == "" {
				return errors.New("organization name must not be empty")
			}

			client := apiclient.New()
			var created *apiclient.Organization
			if err := withStepUp(cmd, client, func(ctx context.Context) error {
				var err error
				created, err = client.CreateOrganization(ctx, name)
				if err != nil {
					return err
				}
				if _, nsErr := client.ReserveNamespace(ctx, name, created.ID); nsErr != nil {
					return fmt.Errorf("organization %q created, but reserve default namespace failed: %w", name, nsErr)
				}
				return nil
			}); err != nil {
				return fmt.Errorf("create organization: %w", err)
			}

			ui.Success("Created organization %s and reserved namespace @%s", sanitizeDisplay(created.Name), sanitizeDisplay(name))
			return nil
		},
	}
}

func newOrgUseCmd() *cobra.Command {
	var personal bool

	c := &cobra.Command{
		Use:   "use [<org-id-or-name>]",
		Short: "Switch active registry organization context (or --personal)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := apiclient.New()
			ctx, cancel := commandContext(cmd, defaultCmdTimeout)
			defer cancel()

			if personal {
				if len(args) > 0 {
					return errors.New("cannot specify an organization alongside --personal")
				}
				if !apiclient.HasSession() {
					return errors.New("not signed in (run 'toob login' first)")
				}
				if _, err := client.Whoami(ctx); err != nil {
					return fmt.Errorf("active session required for personal context: %w", err)
				}
				if err := apiclient.ClearOrganization(); err != nil {
					return fmt.Errorf("switch to personal account: %w", err)
				}
				ui.Success("Switched active context to personal account")
				return nil
			}

			if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
				return errors.New("organization name or ID is required unless --personal is set")
			}
			target := strings.TrimSpace(args[0])

			orgs, err := client.Organizations(ctx)
			if err != nil {
				return fmt.Errorf("lookup organizations: %w", err)
			}
			var matched *apiclient.Organization
			for i := range orgs.Tenants {
				t := &orgs.Tenants[i]
				if t.ID == target || strings.EqualFold(t.Name, target) {
					matched = t
					break
				}
			}
			if matched == nil {
				return fmt.Errorf("organization %q not found among your memberships", target)
			}

			if err := apiclient.ChooseOrganization(matched.ID, matched.Name); err != nil {
				return fmt.Errorf("select organization %q: %w", matched.Name, err)
			}
			ui.Success("Switched active organization to %s (%s)", sanitizeDisplay(matched.Name), sanitizeDisplay(matched.ID))
			return nil
		},
	}

	c.Flags().BoolVar(&personal, "personal", false, "Clear organization selection and use personal account")
	return c
}

func newOrgInviteCmd() *cobra.Command {
	var role string

	c := &cobra.Command{
		Use:   "invite <tenant-id> <email>",
		Short: "Invite a collaborator to an organization",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenantID := strings.TrimSpace(args[0])
			email := strings.TrimSpace(args[1])

			client := apiclient.New()
			var inv *apiclient.Invitation
			if err := withStepUp(cmd, client, func(ctx context.Context) error {
				var err error
				inv, err = client.Invite(ctx, tenantID, email, role)
				return err
			}); err != nil {
				return fmt.Errorf("invite collaborator: %w", err)
			}

			ui.Success("Sent %s invitation to %s (id=%s)", sanitizeDisplay(inv.Role), sanitizeDisplay(inv.Email), shortID(sanitizeDisplay(inv.ID), 12))
			return nil
		},
	}

	c.Flags().StringVar(&role, "role", "member", "Organization role (owner, maintainer, member)")
	return c
}

func newOrgAcceptInviteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "accept-invite <token>",
		Short: "Accept an organization invitation token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			token := strings.TrimSpace(args[0])
			if token == "" {
				return errors.New("invitation token must not be empty")
			}

			ctx, cancel := commandContext(cmd, defaultCmdTimeout)
			defer cancel()

			client := apiclient.New()
			res, err := client.AcceptInvitation(ctx, token)
			if err != nil {
				return fmt.Errorf("accept invitation: %w", err)
			}

			ui.Success("Joined organization %s (role=%s)", sanitizeDisplay(res.Organization.Name), sanitizeDisplay(res.Organization.Role))
			return nil
		},
	}
}

func newOrgLeaveCmd() *cobra.Command {
	var yes bool

	c := &cobra.Command{
		Use:   "leave <tenant-id>",
		Short: "Leave an organization",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenantID := strings.TrimSpace(args[0])
			if tenantID == "" {
				return errors.New("organization ID must not be empty")
			}

			if err := confirmIrreversible(yes, fmt.Sprintf("Leave organization %q? This cannot be undone without a new invite.", tenantID)); err != nil {
				return err
			}

			ctx, cancel := commandContext(cmd, defaultCmdTimeout)
			defer cancel()

			client := apiclient.New()
			if err := client.LeaveOrganization(ctx, tenantID); err != nil {
				return fmt.Errorf("leave organization: %w", err)
			}

			ui.Success("Left organization %s", sanitizeDisplay(tenantID))
			return nil
		},
	}

	c.Flags().BoolVarP(&yes, "yes", "y", false, "Skip interactive confirmation prompt")
	return c
}

func newOrgNamespaceCmd() *cobra.Command {
	nsCmd := &cobra.Command{
		Use:   "namespace",
		Short: "Manage reserved package namespaces (@scope)",
	}

	nsCmd.AddCommand(
		newOrgNamespaceListCmd(),
		newOrgNamespaceReserveCmd(),
	)
	return nsCmd
}

func newOrgNamespaceListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List package namespaces you can publish into",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := commandContext(cmd, defaultCmdTimeout)
			defer cancel()

			client := apiclient.New()
			list, err := client.ListNamespaces(ctx)
			if err != nil {
				return fmt.Errorf("list namespaces: %w", err)
			}

			if len(list) == 0 {
				ui.Info("No namespaces found.")
				return nil
			}
			for _, ns := range list {
				ui.Info("@%-24s id=%s role=%s", sanitizeDisplay(ns.Name), shortID(sanitizeDisplay(ns.ID), 12), sanitizeDisplay(ns.Role))
			}
			return nil
		},
	}
}

func newOrgNamespaceReserveCmd() *cobra.Command {
	var tenantID string

	c := &cobra.Command{
		Use:   "reserve <namespace>",
		Short: "Reserve a new package namespace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			nsName := strings.TrimPrefix(strings.TrimSpace(args[0]), "@")
			if nsName == "" {
				return errors.New("namespace name must not be empty")
			}

			client := apiclient.New()
			var reserved *apiclient.Namespace
			if err := withStepUp(cmd, client, func(ctx context.Context) error {
				var err error
				reserved, err = client.ReserveNamespace(ctx, nsName, tenantID)
				return err
			}); err != nil {
				return fmt.Errorf("reserve namespace: %w", err)
			}

			ui.Success("Reserved namespace @%s", sanitizeDisplay(reserved.Name))
			return nil
		},
	}

	c.Flags().StringVar(&tenantID, "org", "", "Target organization tenant ID (optional)")
	return c
}
