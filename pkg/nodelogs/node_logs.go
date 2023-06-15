/*
Copyright © 2023 Aravindh Puthiyaparambil <aravindhp@gmail.com>
*/

package nodelogs

import (
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

const (
	nodeLogsUsageStr = "node-logs ([--role ROLE] | [--label LABEL] | [NODE...])"
)

var (
	nodeLogsLong = `
		Experimental: Display and filter node logs when the kubelet NodeLogs feature
		flag is set.

		This command retrieves logs for the node. The default mode is to query the
		systemd journal or WinEvent entries on supported operating systems,
		which allows searching, time based filtering, and service based filtering.
		You may also query log files available under /var/logs/ and view those contents
		directly.

		Node logs may contain sensitive output and so are limited to privileged node
		administrators. The system:node-admins role grants this permission by default.
	`

	nodeLogsExample = `
		# Show kubelet and crio journald logs from all masters
		%[1]s node-logs --role master --query kubelet --query crio

		# Show kubelet log file (/var/log/kubelet/kubelet.log) from all Windows worker nodes
		%[1]s node-logs --label kubernetes.io/os=windows --query kubelet

		# Show docker WinEvent logs from a specific Windows worker node
		%[1]s node-logs <node-name> --query docker

		# Show crio journald logs from a specific Linux node
		%[1]s node-logs <node-name> --query crio

		# Show content of file foo.log that is present in /var/log
		%[1]s node-logs <node-name> --query /foo.log
	`
)

type CmdFlags struct {
	configFlags *genericclioptions.ConfigFlags
	genericclioptions.IOStreams
	Query     []string
	Pattern   string
	SinceTime string
	UntilTime string
	Boot      int64
	TailLines int64
	Role      string
	Selector  string
	Raw       bool
	Unify     bool
}

// newCmdFlags provides an instance of CmdFlags with default values
func newCmdFlags(streams genericclioptions.IOStreams) *CmdFlags {
	return &CmdFlags{
		configFlags: genericclioptions.NewConfigFlags(true),
		IOStreams:   streams,
	}
}

// NewCmd provides a cobra command wrapping CmdFlags
func NewCmd(streams genericclioptions.IOStreams) *cobra.Command {
	f := newCmdFlags(streams)

	cmd := &cobra.Command{
		Use:          nodeLogsUsageStr,
		Short:        "Display and filter node logs",
		Example:      fmt.Sprintf(nodeLogsExample, "kubectl"),
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			return nil
		},
	}
	f.AddFlags(cmd)
	return cmd
}

// AddFlags registers flags for a cli.
func (f *CmdFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringSliceVarP(&f.Query, "query", "Q", f.Query,
		"Return log entries that matches any of the specified file or service(s).")
	cmd.Flags().StringVarP(&f.Pattern, "pattern", "p", f.Pattern,
		"Filter log entries by the provided regex pattern. Only applies to service logs.")
	cmd.Flags().StringVar(&f.SinceTime, "since-time", f.SinceTime,
		"Return logs after a specific date (RFC3339). Only applies to service logs.")
	cmd.Flags().StringVar(&f.UntilTime, "until-time", f.UntilTime,
		"Return logs before a specific date (RFC3339). Only applies to service logs.")
	cmd.Flags().Int64Var(&f.Boot, "boot", f.Boot,
		"Show messages from a specific boot. Use negative numbers. "+
			"Passing invalid boot offset will fail retrieving logs. Only applies to Linux service logs.")
	cmd.Flags().Int64Var(&f.TailLines, "tail", f.TailLines,
		"Return up to this many lines (not more than 100k) from the end of the log. Only applies to service logs.")
	cmd.Flags().StringVar(&f.Role, "role", f.Role, "Set a label selector by node role to filter on.")
	cmd.Flags().StringVarP(&f.Selector, "selector", "l", f.Selector, "Selector (label query) to filter on.")
	cmd.Flags().BoolVar(&f.Raw, "raw", f.Raw, "Perform no transformation of the returned data.")
	cmd.Flags().BoolVar(&f.Unify, "unify", f.Unify, "Interleave logs by sorting the output. Defaults on when viewing node journal logs.")
}
