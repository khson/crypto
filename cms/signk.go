package cms

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"

	"github.com/khson/crypto/cms/protocol"
)

type signedDataV2 struct {
	SignV2 asn1.ObjectIdentifier
	Signs  Attributes `asn1:"optional,tag:0"`
}
type Attributes []protocol.SignedData

func SignUseUnSignedAttr(data []byte, chain []*x509.Certificate, signer crypto.Signer, vidSrc []byte) ([]byte, error) {
	sd, err := NewSignedData(data)
	if err != nil {
		return nil, err
	}

	if err = sd.Psd.AddSignerInfoUseUnsignedAttr(chain, signer, vidSrc); err != nil {
		return nil, err
	}

	return asn1.Marshal(*sd.Psd)
}

func SignCrossCertAttr(data []byte, chain []*x509.Certificate, signer crypto.Signer, time []byte, vid []byte, challeange []byte) ([]byte, error) {
	sd, err := NewSignedData(data)
	if err != nil {
		return nil, err
	}

	if err = sd.Psd.AddCrossCertAttr(chain, signer, time, vid, challeange); err != nil {
		return nil, err
	}

	var sigV2 signedDataV2
	sigV2.SignV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	sigV2.Signs = append(sigV2.Signs, *sd.Psd)

	return asn1.Marshal(sigV2)
}

func SignSetDateAttr(data []byte, hashFunc *crypto.Hash, chain []*x509.Certificate, signer crypto.Signer, time string) ([]byte, error) {
	sd, err := NewSignedData(data)
	if err != nil {
		return nil, err
	}

	if err = sd.Psd.AddSetDateAttr(chain, signer, time, hashFunc); err != nil {
		return nil, err
	}

	var sigV2 signedDataV2
	sigV2.SignV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	sigV2.Signs = append(sigV2.Signs, *sd.Psd)

	return asn1.Marshal(sigV2)
}
