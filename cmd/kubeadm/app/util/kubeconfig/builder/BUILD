load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = ["builder.go"],
    importpath = "k8s.io/kubernetes/cmd/kubeadm/app/util/kubeconfig/builder",
    visibility = ["//visibility:public"],
    deps = [
        "//cmd/kubeadm/app/apis/kubeadm:go_default_library",
        "//cmd/kubeadm/app/phases/kubeconfig:go_default_library",
        "//cmd/kubeadm/app/util/kubeconfig:go_default_library",
        "//cmd/kubeadm/app/util/pkiutil:go_default_library",
        "//staging/src/k8s.io/client-go/tools/clientcmd/api:go_default_library",
        "//staging/src/k8s.io/client-go/util/keyutil:go_default_library",
        "//vendor/github.com/pkg/errors:go_default_library",
    ],
)

go_test(
    name = "go_default_test",
    srcs = ["builder_test.go"],
    embed = [":go_default_library"],
    deps = [
        "//cmd/kubeadm/app/apis/kubeadm/v1beta2:go_default_library",
        "//cmd/kubeadm/app/util/config:go_default_library",
        "//cmd/kubeadm/test:go_default_library",
        "//staging/src/k8s.io/apimachinery/pkg/util/sets:go_default_library",
        "//staging/src/k8s.io/client-go/tools/clientcmd:go_default_library",
        "//vendor/github.com/stretchr/testify/assert:go_default_library",
        "//vendor/github.com/stretchr/testify/require:go_default_library",
    ],
)

filegroup(
    name = "package-srcs",
    srcs = glob(["**"]),
    tags = ["automanaged"],
    visibility = ["//visibility:private"],
)

filegroup(
    name = "all-srcs",
    srcs = [":package-srcs"],
    tags = ["automanaged"],
    visibility = ["//visibility:public"],
)
