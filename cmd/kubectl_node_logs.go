/*
Copyright © 2023 Aravindh Puthiyaparambil <aravindhp@gmail.com>
*/
package main

import (
	"os"

	"github.com/aravindhp/kubeclt-node-logs/pkg/nodelogs"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func main() {
	flags := pflag.NewFlagSet("kubectl-node-logs", pflag.ExitOnError)
	pflag.CommandLine = flags

	root := nodelogs.NewCmd(genericclioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr})
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
