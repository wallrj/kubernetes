/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certs

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certutil "k8s.io/client-go/util/cert"
	kubeadmapi "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm"
	"k8s.io/kubernetes/cmd/kubeadm/app/util/pkiutil"
	testutil "k8s.io/kubernetes/cmd/kubeadm/test"
)

func TestCertListOrder(t *testing.T) {
	tests := []struct {
		certs Certificates
		name  string
	}{
		{
			name:  "Default Certificate List",
			certs: GetDefaultCertList(),
		},
		{
			name:  "Cert list less etcd",
			certs: GetCertsWithoutEtcd(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var lastCA *KubeadmCert
			for i, cert := range test.certs {
				if i > 0 && lastCA == nil {
					t.Fatalf("CA not present in list before certificate %q", cert.Name)
				}
				if cert.CAName == "" {
					lastCA = cert
				} else {
					if cert.CAName != lastCA.Name {
						t.Fatalf("expected CA name %q, got %q, for certificate %q", lastCA.Name, cert.CAName, cert.Name)
					}
				}
			}
		})
	}
}

func TestCAPointersValid(t *testing.T) {
	tests := []struct {
		certs Certificates
		name  string
	}{
		{
			name:  "Default Certificate List",
			certs: GetDefaultCertList(),
		},
		{
			name:  "Cert list less etcd",
			certs: GetCertsWithoutEtcd(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			certMap := test.certs.AsMap()

			for _, cert := range test.certs {
				if cert.CAName != "" && certMap[cert.CAName] == nil {
					t.Errorf("Certificate %q references nonexistent CA %q", cert.Name, cert.CAName)
				}
			}
		})
	}
}

func TestMakeCertTree(t *testing.T) {
	rootCert := &KubeadmCert{
		Name: "root",
	}
	leaf0 := &KubeadmCert{
		Name:   "leaf0",
		CAName: "root",
	}
	leaf1 := &KubeadmCert{
		Name:   "leaf1",
		CAName: "root",
	}
	selfSigned := &KubeadmCert{
		Name: "self-signed",
	}

	certMap := CertificateMap{
		"root":        rootCert,
		"leaf0":       leaf0,
		"leaf1":       leaf1,
		"self-signed": selfSigned,
	}

	orphanCertMap := CertificateMap{
		"leaf0": leaf0,
	}

	if _, err := orphanCertMap.CertTree(); err == nil {
		t.Error("expected orphan cert map to error, but got nil")
	}

	certTree, err := certMap.CertTree()
	t.Logf("cert tree: %v", certTree)
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}

	if len(certTree) != 2 {
		t.Errorf("Expected tree to have 2 roots, got %d", len(certTree))
	}

	if len(certTree[rootCert]) != 2 {
		t.Errorf("Expected root to have 2 leaves, got %d", len(certTree[rootCert]))
	}

	if _, ok := certTree[selfSigned]; !ok {
		t.Error("Expected selfSigned to be present in tree, but missing")
	}
}

func TestCreateCertificateChain(t *testing.T) {
	dir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	ic := &kubeadmapi.InitConfiguration{
		NodeRegistration: kubeadmapi.NodeRegistrationOptions{
			Name: "test-node",
		},
		ClusterConfiguration: kubeadmapi.ClusterConfiguration{
			CertificatesDir: dir,
		},
	}

	caCfg := Certificates{
		{
			config:   pkiutil.CertConfig{},
			Name:     "test-ca",
			BaseName: "test-ca",
		},
		{
			config: pkiutil.CertConfig{
				Config: certutil.Config{
					AltNames: certutil.AltNames{
						DNSNames: []string{"test-domain.space"},
					},
					Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				},
			},
			configMutators: []configMutatorsFunc{
				setCommonNameToNodeName(),
			},
			CAName:   "test-ca",
			Name:     "test-daughter",
			BaseName: "test-daughter",
		},
	}

	certTree, err := caCfg.AsMap().CertTree()
	if err != nil {
		t.Fatalf("unexpected error getting tree: %v", err)
	}

	if certTree.CreateTree(ic); err != nil {
		t.Fatal(err)
	}

	caCert, _ := parseCertAndKey(path.Join(dir, "test-ca"), t)
	daughterCert, _ := parseCertAndKey(path.Join(dir, "test-daughter"), t)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	_, err = daughterCert.Verify(x509.VerifyOptions{
		DNSName:   "test-domain.space",
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Errorf("couldn't verify daughter cert: %v", err)
	}

}

func TestLeafCertificates(t *testing.T) {
	errAny := errors.New("match any error")

	type testCase struct {
		name          string
		certificates  Certificates
		result        Certificates
		assertion     func(*testing.T, *testCase)
		setup         func(*testing.T, *testCase)
		expectedError error
	}
	tests := []testCase{
		{
			name: "success",
		},
		{
			name: "nil certs",
			setup: func(t *testing.T, tc *testCase) {
				tc.certificates = nil
				tc.assertion = func(t *testing.T, tc *testCase) {
					assert.Len(t, tc.result, 0)
				}
			},
		},
		{
			name: "no certs",
			setup: func(t *testing.T, tc *testCase) {
				tc.certificates = Certificates{}
				tc.assertion = func(t *testing.T, tc *testCase) {
					assert.Len(t, tc.result, 0)
				}
			},
		},
		{
			name: "error unknown ca",
			setup: func(t *testing.T, tc *testCase) {
				tc.certificates = Certificates{
					{Name: "cert1", CAName: "ca1"},
				}
			},
			expectedError: errAny,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.certificates = Certificates{
				{Name: "ca1"},
				{Name: "ca1-cert1", CAName: "ca1"},
				{Name: "ca1-cert2", CAName: "ca1"},
				{Name: "ca2"},
				{Name: "ca2-cert1", CAName: "ca2"},
			}

			if test.assertion == nil {
				test.assertion = func(t *testing.T, tc *testCase) {
					assert.Len(t, tc.result, 3)
				}
			}

			// A hook to allow tests to change the defaults
			if test.setup != nil {
				test.setup(t, &test)
			}

			var err error
			test.result, err = LeafCertificates(test.certificates)

			if test.expectedError == nil {
				require.NoError(t, err)
				test.assertion(t, &test)
			} else {
				if assert.Error(t, err) {
					if !errors.Is(test.expectedError, errAny) {
						assert.Truef(t, errors.Is(err, test.expectedError), "unexpected error type: %#v", err)
					}
				}
			}

		})
	}
}

func TestCertificatesVisit(t *testing.T) {
	type testCase struct {
		name          string
		certificates  Certificates
		visitor       certificatesVisitor
		expectedError error
		setup         func(t *testing.T, tc *testCase)
		assertion     func(t *testing.T)
	}

	tests := []testCase{
		{
			name: "success",
			setup: func(t *testing.T, tc *testCase) {
				var visited []string
				tc.visitor = func(cert *KubeadmCert) error {
					visited = append(visited, cert.Name)
					return nil
				}
				tc.assertion = func(t *testing.T) {
					assert.Equal(t, []string{"c1", "c2", "c3"}, visited)
				}
			},
		},
		{
			name: "nil certificates",
			setup: func(t *testing.T, tc *testCase) {
				tc.certificates = nil
				tc.visitor = func(cert *KubeadmCert) error {
					panic("should not be called")
				}
			},
		},
		{
			name: "empty certificates",
			setup: func(t *testing.T, tc *testCase) {
				tc.certificates = Certificates{}
				tc.visitor = func(cert *KubeadmCert) error {
					panic("should not be called")
				}
			},
		},
		{
			name: "error nil visitor",
			setup: func(t *testing.T, tc *testCase) {
				tc.visitor = nil
			},
			expectedError: errInvalid,
		},
		{
			name: "visit then error",
			setup: func(t *testing.T, tc *testCase) {
				errSentinel := errors.New("sentinel error")
				var visited []string
				tc.visitor = func(cert *KubeadmCert) error {
					if cert.Name == "c2" {
						return errors.WithStack(errSentinel)
					}
					visited = append(visited, cert.Name)
					return nil
				}
				tc.assertion = func(t *testing.T) {
					assert.Equal(t, []string{"c1"}, visited)
				}
				tc.expectedError = errSentinel
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.certificates == nil {
				test.certificates = Certificates{
					{Name: "c1"},
					{Name: "c2"},
					{Name: "c3"},
				}
			}
			if test.visitor == nil {
				test.visitor = func(cert *KubeadmCert) error {
					t.Fail()
					return nil
				}
			}
			if test.setup != nil {
				test.setup(t, &test)
			}
			err := test.certificates.visit(test.visitor)
			if test.expectedError == nil {
				require.NoError(t, err)
			} else {
				if assert.Error(t, err) {
					assert.Truef(t, errors.Is(err, test.expectedError), "unexpected error: %v", err)
				}
			}
			if test.assertion != nil {
				test.assertion(t)
			}
		})
	}

}

func TestKeyAndCSRCreatorCreate(t *testing.T) {
	touch := func(t *testing.T, existingFile string) {
		existingDir := filepath.Dir(existingFile)
		require.NoError(t, os.MkdirAll(existingDir, os.FileMode(0700)))
		file, err := os.Create(existingFile)
		require.NoError(t, err)
		require.NoError(t, file.Close())
	}

	type testCase struct {
		name          string
		creator       *keyAndCSRCreator
		cert          *KubeadmCert
		tmpDir        string
		setup         func(t *testing.T, tc *testCase)
		assertion     func(t *testing.T, tc *testCase)
		expectedError error
	}
	tests := []testCase{
		{
			name: "success",
		},
		{
			name: "error nil object",
			setup: func(t *testing.T, tc *testCase) {
				tc.creator = nil
			},
			expectedError: errInvalid,
		},
		{
			name: "error nil cert",
			setup: func(t *testing.T, tc *testCase) {
				tc.cert = nil
			},
			expectedError: errInvalid,
		},
		{
			name: "error key file exists",
			setup: func(t *testing.T, tc *testCase) {
				certDir := tc.creator.kubeadmConfig.ClusterConfiguration.CertificatesDir
				touch(t, certDir+"/"+tc.cert.BaseName+".key")
			},
			expectedError: errExist,
		},
		{
			name: "error CSR file exists",
			setup: func(t *testing.T, tc *testCase) {
				certDir := tc.creator.kubeadmConfig.ClusterConfiguration.CertificatesDir
				touch(t, certDir+"/"+tc.cert.BaseName+".csr")
			},
			expectedError: errExist,
		},
		{
			name: "error permission denied while creating key",
			setup: func(t *testing.T, tc *testCase) {
				certDir := tc.creator.kubeadmConfig.ClusterConfiguration.CertificatesDir
				require.NoError(t, os.Chmod(certDir, 0500))
			},
			expectedError: os.ErrPermission,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tmpDir := testutil.SetupTempDir(t)
			defer os.RemoveAll(tmpDir)

			test.creator = &keyAndCSRCreator{
				kubeadmConfig: &kubeadmapi.InitConfiguration{
					ClusterConfiguration: kubeadmapi.ClusterConfiguration{
						CertificatesDir: tmpDir,
					},
				},
			}
			test.cert = &KubeadmCert{BaseName: "cert1"}

			if test.assertion == nil && test.expectedError == nil {
				test.assertion = func(t *testing.T, tc *testCase) {
					certDir := tc.creator.kubeadmConfig.ClusterConfiguration.CertificatesDir
					assert.FileExists(t, certDir+"/"+tc.cert.BaseName+".key")
					assert.FileExists(t, certDir+"/"+tc.cert.BaseName+".csr")
				}
			}

			// A hook to allow tests to change the defaults
			if test.setup != nil {
				test.setup(t, &test)
			}

			err := test.creator.create(test.cert)
			if test.expectedError == nil {
				require.NoError(t, err)
			} else {
				if assert.Error(t, err) {
					assert.Truef(t, errors.Is(err, test.expectedError), "unexpected error type: %#v", err)
				}
			}
			if test.assertion != nil {
				test.assertion(t, &test)
			}
		})
	}
}

func TestCreateKeyAndCSRFiles(t *testing.T) {
	tmpDir := testutil.SetupTempDir(t)
	defer os.RemoveAll(tmpDir)

	err := CreateKeyAndCSRFiles(
		&kubeadmapi.InitConfiguration{
			ClusterConfiguration: kubeadmapi.ClusterConfiguration{
				CertificatesDir: tmpDir,
			},
		},
		Certificates{
			{BaseName: "cert1"},
		},
	)
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(tmpDir, "cert1.key"))
	assert.FileExists(t, filepath.Join(tmpDir, "cert1.csr"))
}

func parseCertAndKey(basePath string, t *testing.T) (*x509.Certificate, crypto.PrivateKey) {
	certPair, err := tls.LoadX509KeyPair(basePath+".crt", basePath+".key")
	if err != nil {
		t.Fatalf("couldn't parse certificate and key: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(certPair.Certificate[0])
	if err != nil {
		t.Fatalf("couldn't parse certificate: %v", err)
	}

	return parsedCert, certPair.PrivateKey
}
