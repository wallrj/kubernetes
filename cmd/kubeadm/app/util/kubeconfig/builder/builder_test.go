package builder_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/clientcmd"
	kubeadmapiv1beta2 "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm/v1beta2"
	configutil "k8s.io/kubernetes/cmd/kubeadm/app/util/config"
	"k8s.io/kubernetes/cmd/kubeadm/app/util/kubeconfig/builder"
	testutil "k8s.io/kubernetes/cmd/kubeadm/test"
)

func verifyFiles(t *testing.T, baseDir string, expectedPaths sets.String, expectedClusterName string) {
	actualPaths := sets.NewString()
	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			if path == baseDir {
				return nil
			}
			listing, err := ioutil.ReadDir(path)
			require.NoError(t, err)
			if len(listing) > 0 {
				return nil
			}
		}
		actualPaths.Insert(path)
		return nil
	})
	require.NoError(t, err)

	missingPaths := expectedPaths.Difference(actualPaths)
	assert.Empty(t, missingPaths.List(), "missing paths")

	unexpectedPaths := actualPaths.Difference(expectedPaths)
	assert.Empty(t, unexpectedPaths.List(), "unexpected paths")

	filesWithUnexpectedExtensions := sets.NewString()

	for path := range expectedPaths {
		switch filepath.Ext(path) {
		case ".csr":
		case ".conf":
			conf, err := clientcmd.LoadFromFile(path)
			if assert.NoError(t, err) {
				_, found := conf.Clusters[expectedClusterName]
				assert.True(t, found, "cluster name not found")
			}
		default:
			filesWithUnexpectedExtensions.Insert(path)
		}
	}
	assert.Empty(t, filesWithUnexpectedExtensions.List(), "files with unexpected file extensions")
}

func expectedFiles(kubeConfigDir string, expectedExtensions ...string) sets.String {
	baseNames := []string{
		"admin",
		"controller-manager",
		"kubelet",
		"scheduler",
	}
	expected := sets.NewString()
	for _, baseName := range baseNames {
		for _, ext := range expectedExtensions {
			expected.Insert(kubeConfigDir + "/" + baseName + ext)
		}
	}
	return expected
}

func TestBuilder(t *testing.T) {
	kubeConfigDir := testutil.SetupTempDir(t)
	defer os.RemoveAll(kubeConfigDir)

	defaultInitConfiguration, err := configutil.DefaultedInitConfiguration(
		&kubeadmapiv1beta2.InitConfiguration{},
		&kubeadmapiv1beta2.ClusterConfiguration{},
	)
	require.NoError(t, err)

	tests := []struct {
		name          string
		options       []builder.BuilderOption
		expectedFiles sets.String
	}{
		{
			name: "unconfigured",
		},
		{
			name: "default kubeconfig files",
			options: []builder.BuilderOption{
				builder.WithDefaultKubeConfigs(defaultInitConfiguration),
			},
			expectedFiles: expectedFiles(kubeConfigDir, ".conf"),
		},
		{
			name: "csr generation",
			options: []builder.BuilderOption{
				builder.WithDefaultKubeConfigs(defaultInitConfiguration),
				builder.WithCSRGeneration(),
			},
			expectedFiles: expectedFiles(kubeConfigDir, ".conf", ".conf.csr"),
		},
	}

	defaultOptions := []builder.BuilderOption{
		builder.WithKubeConfigDir(kubeConfigDir),
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Log(test.name)
			options := append(defaultOptions, test.options...)
			b, err := builder.New(options...)
			assert.NoError(t, err)
			err = b.BuildAll()
			assert.NoError(t, err)
			verifyFiles(t, kubeConfigDir, test.expectedFiles, "")
		})
	}
}
