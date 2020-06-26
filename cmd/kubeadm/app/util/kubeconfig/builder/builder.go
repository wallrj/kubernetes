package builder

import (
	"crypto"
	"fmt"
	"path/filepath"

	"github.com/pkg/errors"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/util/keyutil"

	kubeadmapi "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm"
	kubeconfigphase "k8s.io/kubernetes/cmd/kubeadm/app/phases/kubeconfig"
	kubeconfigutil "k8s.io/kubernetes/cmd/kubeadm/app/util/kubeconfig"
	"k8s.io/kubernetes/cmd/kubeadm/app/util/pkiutil"
)

type Builder struct {
	kubeConfigMap kubeconfigphase.KubeConfigMap
	kubeConfigDir string
	clusterName   string
	caCert        []byte
	csrGeneration bool
}

type BuilderOption func(*Builder) error

func WithDefaultKubeConfigs(cfg *kubeadmapi.InitConfiguration) BuilderOption {
	return func(builder *Builder) (err error) {
		builder.kubeConfigMap, err = kubeconfigphase.GetDefaultKubeConfigMap(cfg)
		if err != nil {
			return errors.Wrap(err, "failed to get default kubeconfig map")
		}
		return nil
	}
}

func WithKubeConfigDir(kubeConfigDir string) BuilderOption {
	return func(builder *Builder) (err error) {
		builder.kubeConfigDir = kubeConfigDir
		return nil
	}
}

func WithClusterName(clusterName string) BuilderOption {
	return func(builder *Builder) (err error) {
		builder.clusterName = clusterName
		return nil
	}
}

func WithCSRGeneration() BuilderOption {
	return func(builder *Builder) (err error) {
		builder.csrGeneration = true
		return nil
	}
}

func New(options ...BuilderOption) (*Builder, error) {
	var builder Builder
	for _, option := range options {
		if err := option(&builder); err != nil {
			return nil, errors.Wrap(err, "failed to apply modifier")
		}
	}
	return &builder, nil
}

func (o *Builder) buildOne(fileName string) error {
	spec, exists := o.kubeConfigMap[fileName]
	if !exists {
		return fmt.Errorf("kubeconfig not found in map: %s", fileName)
	}

	userName := spec.ClientName

	config := kubeconfigutil.CreateBasic(spec.APIServer, o.clusterName, userName, o.caCert)
	var authInfo clientcmdapi.AuthInfo

	if spec.TokenAuth != nil {
		authInfo.Token = spec.TokenAuth.Token
	}

	if spec.ClientCertAuth != nil {
		clientCertConfig := spec.ToClientCertConfig()
		var clientKey crypto.Signer

		clientKey, err := pkiutil.NewPrivateKey(clientCertConfig.PublicKeyAlgorithm)
		if err != nil {
			return errors.Wrap(err, "failed to create private key")
		}
		encodedClientKey, err := keyutil.MarshalPrivateKeyToPEM(clientKey)
		if err != nil {
			return errors.Wrap(err, "failed to marshal private key to PEM")
		}
		authInfo.ClientKeyData = encodedClientKey

		if spec.ClientCertAuth.CAKey != nil && spec.CACert != nil {
			clientCert, err := pkiutil.NewSignedCert(&clientCertConfig, clientKey, spec.CACert, spec.ClientCertAuth.CAKey)
			if err != nil {
				return errors.Wrapf(err, "failure while creating %s client certificate", spec.ClientName)
			}
			authInfo.ClientCertificateData = pkiutil.EncodeCertPEM(clientCert)
		}

		if o.csrGeneration {
			clientCSR, err := pkiutil.NewCSR(clientCertConfig, clientKey)
			if err != nil {
				return errors.Wrapf(err, "failure while creating %s client csr", spec.ClientName)
			}
			if err := pkiutil.WriteCSR(o.kubeConfigDir, fileName, clientCSR); err != nil {
				return errors.Wrap(err, "failed to write CSR file")
			}
		}
	}

	config.AuthInfos[userName] = &authInfo

	kubeConfigFilePath := filepath.Join(o.kubeConfigDir, fileName)
	if err := kubeconfigutil.WriteToDisk(kubeConfigFilePath, config); err != nil {
		return errors.Wrapf(err, "failed to save kubeconfig file %q on disk", kubeConfigFilePath)
	}
	return nil
}

func (o *Builder) BuildAll() error {
	for name := range o.kubeConfigMap {
		if err := o.buildOne(name); err != nil {
			return errors.Wrapf(err, "failed to build: %s", name)
		}
	}
	return nil
}
