# Kubernetes Node Log viewer
`kubectl-node-logs` is a kubectl plugin for viewing and filtering node logs based on the 
[oc adm node-logs](https://github.com/openshift/oc/blob/master/pkg/cli/admin/node/logs.go)
implementation.

## Prerequisites
- Kubernetes cluster 1.27+
  - `NodeLogQuery` [feature gate](https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/) is
     enabled on the node(s)
  - [Kubelet configuration options](https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/#kubelet-config-k8s-io-v1beta1-KubeletConfiguration)
    `enableSystemLogHandler` and `enableSystemLogQuery` are both set to true
  - Authorized to interact with node objects
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/) version 1.27+
- [Go](https://golang.org/doc/install) version 1.21

## Installation

### From source
```shell
$ git clone https://github.com/aravindhp/kubectl-node-logs.git
$ cd kubectl-node-logs
$ go build -o kubectl-node_logs cmd/kubectl_node_logs.go
$ mv kubectl-node_logs /$USER/.local/bin # or any other directory in $PATH
```

## Usage
Here is an example to retrieve the kubelet service logs from a node:
```shell
# Fetch kubelet logs from a node named node-1.example
$ kubectl node-logs node-1.example --query=kubelet
```

You can also fetch files, provided that the files are in a directory that the kubelet allows for log fetches. For
example, you can fetch a log from /var/log/ on a node:
```shell
 kubectl node-logs node-1.example --query /foo.log
```

For further options, please see `kubectl node-logs --help`

## Further reading

- [Kubernetes Cluster Administration -> System Logs -> Log query](https://kubernetes.io/docs/concepts/cluster-administration/system-logs/#log-query)
- Kubernetes 1.27 Blog post: [Query Node Logs Using The Kubelet API](https://www.openshift.com/blog/kubernetes-1-27-query-node-logs-using-the-kubelet-api)
