/*
Copyright © 2023 Aravindh Puthiyaparambil <aravindhp@gmail.com>
*/

package nodelogs

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	"k8s.io/client-go/rest"
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
		Use:                   nodeLogsUsageStr,
		DisableFlagsInUseLine: true,
		Short:                 "Display and filter node logs",
		Long:                  nodeLogsLong,
		Example:               fmt.Sprintf(nodeLogsExample, "kubectl"),
		SilenceUsage:          true,
		Run: func(cmd *cobra.Command, args []string) {
			o, err := f.ToOptions(args, cmd.Flags().Changed("boot"))
			kcmdutil.CheckErr(err)
			kcmdutil.CheckErr(o.Validate())
			kcmdutil.CheckErr(o.Run())
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
	f.configFlags.AddFlags(cmd.Flags())
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
	o.RESTClientGetter = factory.UnstructuredClientForMapping

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

// Run retrieves node logs
func (o *CmdOptions) Run() error {
	builder := o.Builder

	var requests []*logRequest

	var errs []error
	result := builder.ContinueOnError().Flatten().Do()
	err := result.Visit(func(info *resource.Info, err error) error {
		if err != nil {
			requests = append(requests, &logRequest{node: info.Name, err: err})
			return nil
		}
		mapping := info.ResourceMapping()
		client, err := o.RESTClientGetter(mapping)
		if err != nil {
			requests = append(requests, &logRequest{node: info.Name, err: err})
			return nil
		}

		path := client.Get().
			Namespace(info.Namespace).Name(info.Name).
			Resource(mapping.Resource.Resource).SubResource("proxy", "logs").URL().Path
		req := client.Get().RequestURI(path).
			SetHeader("Accept", "text/plain, */*").
			SetHeader("Accept-Encoding", "gzip")

		if len(o.Query) > 0 {
			for _, query := range o.Query {
				req.Param("query", query)
			}
		}
		if o.UntilTime != nil {
			req.Param("untilTime", o.UntilTime.Format(time.RFC3339))
		}
		if o.SinceTime != nil {
			req.Param("sinceTime", o.SinceTime.Format(time.RFC3339))
		}
		if o.Boot != nil {
			req.Param("boot", strconv.FormatInt(*o.Boot, 10))
		}
		if len(o.Pattern) > 0 {
			req.Param("pattern", o.Pattern)
		}
		if o.TailLines != nil && *o.TailLines > 0 {
			req.Param("tailLines", strconv.FormatInt(*o.TailLines, 10))
		}

		requests = append(requests, &logRequest{
			node: info.Name,
			req:  req,
			raw:  o.Raw || len(o.Query) > 0,
		})
		return nil
	})
	if err != nil {
		if agg, ok := err.(errors.Aggregate); ok {
			errs = append(errs, agg.Errors()...)
		} else {
			errs = append(errs, err)
		}
	}

	found := len(errs) + len(requests)
	// only hide prefix if the user specified a single item
	skipPrefix := found == 1 && result.TargetsSingleItems()

	// buffer output for slightly better streaming performance
	out := bufio.NewWriterSize(o.Out, 1024*16)
	defer out.Flush()

	if o.Unify {
		// unified output is each source, interleaved in lexographic order (assumes
		// the source input is sorted by time)
		var readers []Reader
		for i := range requests {
			req := requests[i]
			req.skipPrefix = true
			pr, pw := io.Pipe()
			readers = append(readers, Reader{
				R: pr,
			})
			go func() {
				err := req.WriteRequest(pw)
				pw.CloseWithError(err)
			}()
		}
		_, err := NewMergeReader(readers...).WriteTo(out)
		if agg := errors.Flatten(errors.NewAggregate([]error{err})); agg != nil {
			errs = append(errs, agg.Errors()...)
		}

	} else {
		// display files sequentially
		for _, req := range requests {
			req.skipPrefix = skipPrefix
			if err := req.WriteRequest(out); err != nil {
				errs = append(errs, err)
			}
		}
	}

	if len(errs) > 0 {
		for _, err := range errs {
			fmt.Fprintf(o.ErrOut, "error: %v\n", err)
			if err, ok := err.(*apierrors.StatusError); ok && err.ErrStatus.Details != nil {
				for _, cause := range err.ErrStatus.Details.Causes {
					fmt.Fprintf(o.ErrOut, "  %s\n", cause.Message)
				}
			}
		}
		return kcmdutil.ErrExit
	}

	return nil
}

// logRequest abstracts retrieving the content of the node logs endpoint which is normally
// either directory content or a file. It supports raw retrieval for use with the journal
// endpoint, and formats the HTML returned by a directory listing into a more user friendly
// output.
type logRequest struct {
	node string
	req  *rest.Request
	err  error

	// raw is set to true when we are viewing the journal and wish to skip prefixing
	raw bool
	// skipPrefix bypasses prefixing if the user knows that a unique identifier is already
	// in the file
	skipPrefix bool
}

// WriteRequest prefixes the error message with the current node if necessary
func (req *logRequest) WriteRequest(out io.Writer) error {
	if req.err != nil {
		return req.err
	}
	err := req.writeTo(out)
	if err != nil {
		req.err = err
	}
	return err
}

func (req *logRequest) writeTo(out io.Writer) error {
	in, err := req.req.Stream(context.TODO())
	if err != nil {
		return err
	}
	defer in.Close()

	// raw output implies we may be getting binary content directly
	// from the remote and so we want to perform no translation
	if req.raw {
		// TODO: optionallyDecompress should be implemented by checking
		// the content-encoding of the response, but we perform optional
		// decompression here in case the content of the logs on the server
		// is also gzipped.
		return optionallyDecompress(out, in)
	}

	var prefix []byte
	if !req.skipPrefix {
		prefix = []byte(fmt.Sprintf("%s ", req.node))
	}

	return outputDirectoryEntriesOrContent(out, in, prefix)
}

func optionallyDecompress(out io.Writer, in io.Reader) error {
	bufferSize := 4096
	buf := bufio.NewReaderSize(in, bufferSize)
	head, err := buf.Peek(1024)
	if err != nil && err != io.EOF {
		return err
	}
	if _, err := gzip.NewReader(bytes.NewBuffer(head)); err != nil {
		// not a gzipped stream
		_, err = io.Copy(out, buf)
		return err
	}
	r, err := gzip.NewReader(buf)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, r)
	return err
}

func outputDirectoryEntriesOrContent(out io.Writer, in io.Reader, prefix []byte) error {
	bufferSize := 4096
	buf := bufio.NewReaderSize(in, bufferSize)

	// turn href links into lines of output
	content, _ := buf.Peek(bufferSize)
	if bytes.HasPrefix(content, []byte("<pre>")) {
		reLink := regexp.MustCompile(`href="([^"]+)"`)
		s := bufio.NewScanner(buf)
		s.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
			matches := reLink.FindSubmatchIndex(data)
			if matches == nil {
				advance = bytes.LastIndex(data, []byte("\n"))
				if advance == -1 {
					advance = 0
				}
				return advance, nil, nil
			}
			advance = matches[1]
			token = data[matches[2]:matches[3]]
			return advance, token, nil
		})
		for s.Scan() {
			if _, err := out.Write(prefix); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(out, s.Text()); err != nil {
				return err
			}
		}
		return s.Err()
	}

	// without a prefix we can copy directly
	if len(prefix) == 0 {
		_, err := io.Copy(out, buf)
		return err
	}

	r := NewMergeReader(Reader{R: buf, Prefix: prefix})
	_, err := r.WriteTo(out)
	return err
}

// Reader wraps an io.Reader and inserts the provided prefix at the
// beginning of the output and before each newline character found
// in the stream.
type Reader struct {
	R      io.Reader
	Prefix []byte
}

type mergeReader []Reader

// NewMergeReader attempts to display the provided readers as line
// oriented output in lexographic order by always reading the next
// available line from the reader with the "smallest" line.
//
// For example, given the readers with the following lines:
//
//	 1: A
//	    B
//	    D
//	 2: C
//	    D
//	    E
//
//	the reader would contain:
//	    A
//	    B
//	    C
//	    D
//	    D
//	    E
//
// The merge reader uses bufio.NewReader() for each input and the
// ReadLine() method to find the next shortest input. If a given
// line is longer than the buffer size of 4096, and all readers
// have the same initial 4096 characters, the order is undefined.
func NewMergeReader(r ...Reader) io.WriterTo {
	return mergeReader(r)
}

// WriteTo copies the provided readers into the provided output.
func (r mergeReader) WriteTo(out io.Writer) (int64, error) {
	// shortcut common cases
	switch len(r) {
	case 0:
		return 0, nil
	case 1:
		if len(r[0].Prefix) == 0 {
			return io.Copy(out, r[0].R)
		}
	}

	// initialize the buffered readers
	bufSize := 4096
	var buffers sortedBuffers
	var errs []error
	for _, in := range r {
		buf := &buffer{
			r:      bufio.NewReaderSize(in.R, bufSize),
			prefix: in.Prefix,
		}
		if err := buf.next(); err != nil {
			errs = append(errs, err)
			continue
		}
		buffers = append(buffers, buf)
	}

	var n int64
	for len(buffers) > 0 {
		// find the lowest buffer
		sort.Sort(buffers)

		// write out the line from the smallest buffer
		buf := buffers[0]

		if len(buf.prefix) > 0 {
			b, err := out.Write(buf.prefix)
			n += int64(b)
			if err != nil {
				return n, err
			}
		}

		for {
			done := !buf.linePrefix
			b, err := out.Write(buf.line)
			n += int64(b)
			if err != nil {
				return n, err
			}

			// try to fill the buffer, and if we get an error reading drop this source
			if err := buf.next(); err != nil {
				errs = append(errs, err)
				buffers = buffers[1:]
				break
			}

			// we reached the end of our line
			if done {
				break
			}
		}
		b, err := fmt.Fprintln(out)
		n += int64(b)
		if err != nil {
			return n, err
		}
	}

	return n, errors.FilterOut(errors.NewAggregate(errs), func(err error) bool { return err == io.EOF })
}

type buffer struct {
	r          *bufio.Reader
	prefix     []byte
	line       []byte
	linePrefix bool
}

func (b *buffer) next() error {
	var err error
	b.line, b.linePrefix, err = b.r.ReadLine()
	return err
}

type sortedBuffers []*buffer

func (buffers sortedBuffers) Less(i, j int) bool {
	return bytes.Compare(buffers[i].line, buffers[j].line) < 0
}
func (buffers sortedBuffers) Swap(i, j int) {
	buffers[i], buffers[j] = buffers[j], buffers[i]
}
func (buffers sortedBuffers) Len() int {
	return len(buffers)
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
