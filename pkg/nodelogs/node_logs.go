/*
Copyright © 2023 Aravindh Puthiyaparambil <aravindhp@gmail.com>
*/

package nodelogs

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	kcmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/scheme"
	"k8s.io/kubectl/pkg/util"
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
		Long:         nodeLogsLong,
		Example:      fmt.Sprintf(nodeLogsExample, "kubectl"),
		SilenceUsage: true,
		Run: func(cmd *cobra.Command, args []string) {
			o, err := f.ToOptions(args, cmd.Flags().Changed("boot"))
			kcmdutil.CheckErr(err)
			kcmdutil.CheckErr(o.Validate())
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

// ToOptions converts from CLI inputs to runtime inputs.
func (f *CmdFlags) ToOptions(args []string, bootChanged bool) (*CmdOptions, error) {
	o := &CmdOptions{
		Unify:     f.Unify,
		Raw:       f.Raw,
		Resources: args,
		IOStreams: f.IOStreams,
	}

	if bootChanged {
		o.Boot = &f.Boot
	}

	if len(f.Query) > 0 {
		o.Query = f.Query
	}

	files, services := parseQuery(f.Query)
	if files == 0 || services > 0 {
		o.Raw = true
		o.Unify = true
	}

	if len(f.SinceTime) > 0 {
		t, err := util.ParseRFC3339(f.SinceTime, metav1.Now)
		if err != nil {
			return nil, err
		}

		o.SinceTime = &t
	}

	if len(f.UntilTime) > 0 {
		t, err := util.ParseRFC3339(f.UntilTime, metav1.Now)
		if err != nil {
			return nil, err
		}

		o.UntilTime = &t
	}

	if len(f.Pattern) > 0 {
		o.Pattern = f.Pattern
	}

	if f.TailLines > 0 {
		o.TailLines = &f.TailLines
	}

	var nodeSelectorTail int64 = 10
	if len(f.Selector) > 0 && o.TailLines == nil {
		o.TailLines = &nodeSelectorTail
	}

	factory := kcmdutil.NewFactory(f.configFlags)
	builder := factory.NewBuilder().
		WithScheme(scheme.Scheme, scheme.Scheme.PrioritizedVersionsAllGroups()...).
		SingleResourceType()

	if len(o.Resources) > 0 {
		builder.ResourceNames("nodes", o.Resources...)
	}
	if len(o.Role) > 0 {
		req, err := labels.NewRequirement(fmt.Sprintf("node-role.kubernetes.io/%s", o.Role), selection.Exists, nil)
		if err != nil {
			return nil, fmt.Errorf("invalid --role: %v", err)
		}
		o.Selector = req.String()
	}
	if len(o.Selector) > 0 {
		builder.ResourceTypes("nodes").LabelSelectorParam(o.Selector)
	}
	o.Builder = builder

	return o, nil
}

type CmdOptions struct {
	Resources []string
	Selector  string
	Role      string

	Query     []string
	Pattern   string
	Boot      *int64
	SinceTime *metav1.Time
	UntilTime *metav1.Time
	TailLines *int64
	// output format arguments
	// raw is set to true when we are viewing the journal and wish to skip prefixing
	Raw    bool
	Unify  bool
	Prefix bool

	RESTClientGetter func(mapping *meta.RESTMapping) (resource.RESTClient, error)
	Builder          *resource.Builder

	genericclioptions.IOStreams
}

func (o *CmdOptions) Validate() error {
	if len(o.Resources) == 0 && len(o.Selector) == 0 {
		return fmt.Errorf("at least one node name or a selector (-l) must be specified")
	}
	if len(o.Resources) > 0 && len(o.Selector) > 0 {
		return fmt.Errorf("node names and selector may not both be specified")
	}
	if o.TailLines != nil && *o.TailLines < -1 {
		return fmt.Errorf("--tail must be greater than or equal to -1")
	}
	if o.Boot != nil && (*o.Boot < -100 || *o.Boot > 0) {
		return fmt.Errorf("--boot accepts values [-100, 0]")
	}
	return nil
}

// parseQuery traverses the query slice and returns the number of files and services
func parseQuery(query []string) (int, int) {
	var files, services int
	for _, q := range query {
		if strings.ContainsAny(q, "/\\") {
			files++
		} else {
			services++
		}
	}
	return files, services
}
