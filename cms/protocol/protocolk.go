package protocol

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"strconv"
	"time"

	"github.com/khson/crypto/cms/oid"
)

type PotVID struct {
	IDN string `asn1:"printable"`
	RN  asn1.BitString
}
type CrossCertVid struct {
	oid  asn1.ObjectIdentifier
	data asn1.BitString
}

func (sd *SignedData) AddSignerInfoUseUnsignedAttr(chain []*x509.Certificate, signer crypto.Signer, vidSrc []byte) error {

	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}

	var (
		cert    *x509.Certificate
		certPub []byte
	)

	for _, c := range chain {
		if err = sd.AddCertificate(c); err != nil {
			return err
		}

		if certPub, err = x509.MarshalPKIXPublicKey(c.PublicKey); err != nil {
			return err
		}

		if bytes.Equal(pub, certPub) {
			cert = c
		}
	}
	if cert == nil {
		return ErrNoCertificate
	}

	sid, err := NewIssuerAndSerialNumber(cert)
	if err != nil {
		return err
	}

	digestAlgorithm := digestAlgorithmForPublicKey(pub)
	signatureAlgorithm, ok := oid.X509PublicKeyAlgorithmToPKIXAlgorithmIdentifier[cert.PublicKeyAlgorithm]
	if !ok {
		return errors.New("unsupported certificate public key algorithm")
	}

	si := SignerInfo{
		Version:            1,
		SID:                sid,
		DigestAlgorithm:    digestAlgorithm,
		SignedAttrs:        nil,
		SignatureAlgorithm: signatureAlgorithm,
		Signature:          nil,
		UnsignedAttrs:      nil,
	}

	// Get the message
	content, err := sd.EncapContentInfo.EContentValue()
	if err != nil {
		return err
	}
	if content == nil {
		return errors.New("already detached")
	}

	// Digest the message.
	hash, err := si.Hash()
	if err != nil {
		return err
	}
	md := hash.New()
	if _, err = md.Write(content); err != nil {
		return err
	}
	mdB := md.Sum(nil)

	ust, err := NewAttribute(oid.AttributeKoscomType, vidSrc)
	si.UnsignedAttrs = append(si.UnsignedAttrs, ust)

	if err != nil {
		return err
	}

	if si.Signature, err = signer.Sign(rand.Reader, mdB, hash); err != nil {
		return err
	}

	sd.addDigestAlgorithm(si.DigestAlgorithm)

	sd.SignerInfos = append(sd.SignerInfos, si)

	return nil
}

func (sd *SignedData) AddCrossCertAttr(chain []*x509.Certificate, signer crypto.Signer, t []byte, vid []byte, challeange []byte) error {
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}

	var (
		cert    *x509.Certificate
		certPub []byte
	)

	for _, c := range chain {
		if err = sd.AddCertificate(c); err != nil {
			return err
		}

		if certPub, err = x509.MarshalPKIXPublicKey(c.PublicKey); err != nil {
			return err
		}

		if bytes.Equal(pub, certPub) {
			cert = c
		}
	}
	if cert == nil {
		return ErrNoCertificate
	}

	sid, err := NewIssuerAndSerialNumber(cert)
	if err != nil {
		return err
	}

	digestAlgorithm := digestAlgorithmForPublicKey(pub)
	signatureAlgorithm, ok := oid.X509PublicKeyAlgorithmToPKIXAlgorithmIdentifier[cert.PublicKeyAlgorithm]
	if !ok {
		return errors.New("unsupported certificate public key algorithm")
	}

	si := SignerInfo{
		Version:            1,
		SID:                sid,
		DigestAlgorithm:    digestAlgorithm,
		SignedAttrs:        nil,
		SignatureAlgorithm: signatureAlgorithm,
		Signature:          nil,
		UnsignedAttrs:      nil,
	}

	// Get the message
	content, err := sd.EncapContentInfo.EContentValue()
	if err != nil {
		return err
	}
	if content == nil {
		return errors.New("already detached")
	}
	si.DigestAlgorithm.Parameters.Tag = 5
	si.SignatureAlgorithm.Parameters.Tag = 5
	// Digest the message.
	hash, err := si.Hash()
	if err != nil {
		return err
	}
	md := hash.New()
	if _, err = md.Write(content); err != nil {
		return err
	}
	format := "060102150405Z"
	utcTime, err := time.Parse(format, string(t))
	if err != nil {
		return err
	}
	//utcTime = utcTime.In(time.FixedZone("KST",9*60*60))
	utcTime = utcTime.UTC()

	// Build our SignedAttributes
	stAttr, err := NewAttribute(oid.AttributeSigningTime, utcTime)
	if err != nil {
		return err
	}
	mdAttr, err := NewAttribute(oid.AttributeMessageDigest, md.Sum(nil))
	if err != nil {
		return err
	}
	ctAttr, err := NewAttribute(oid.AttributeContentType, sd.EncapContentInfo.EContentType)
	if err != nil {
		return err
	}

	si.SignedAttrs = append(si.SignedAttrs, ctAttr, stAttr, mdAttr)

	// Signature is over the marshaled signed attributes
	sm, err := si.SignedAttrs.MarshaledForSigning()
	if err != nil {
		return err
	}
	smd := hash.New()
	if _, errr := smd.Write(sm); errr != nil {
		return errr
	}

	if si.Signature, err = signer.Sign(rand.Reader, smd.Sum(nil), hash); err != nil {
		return err
	}

	sd.addDigestAlgorithm(si.DigestAlgorithm)
	if vid != nil {
		crossVid, err := NewAttribute(oid.CrossWebVidType, vid)
		if err != nil {
			return err
		}
		si.UnsignedAttrs = append(si.UnsignedAttrs, crossVid)
	}
	if challeange != nil {
		corssReplay, err := NewAttribute(oid.CrossWebReplayType, challeange)
		if err != nil {
			return err
		}
		si.UnsignedAttrs = append(si.UnsignedAttrs, corssReplay)
	}

	sd.SignerInfos = append(sd.SignerInfos, si)

	return nil
}

func (sd *SignedData) AddSetDateAttr(chain []*x509.Certificate, signer crypto.Signer, t string, hashFunc *crypto.Hash) error {
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}

	var (
		cert    *x509.Certificate
		certPub []byte
	)

	for _, c := range chain {
		if err = sd.AddCertificate(c); err != nil {
			return err
		}

		if certPub, err = x509.MarshalPKIXPublicKey(c.PublicKey); err != nil {
			return err
		}

		if bytes.Equal(pub, certPub) {
			cert = c
		}
	}
	if cert == nil {
		return ErrNoCertificate
	}

	sid, err := NewIssuerAndSerialNumber(cert)
	if err != nil {
		return err
	}

	digestAlgorithm := digestAlgorithmForPublicKey(pub)
	signatureAlgorithm, ok := oid.X509PublicKeyAlgorithmToPKIXAlgorithmIdentifier[cert.PublicKeyAlgorithm]
	if !ok {
		return errors.New("unsupported certificate public key algorithm")
	}

	si := SignerInfo{
		Version:            1,
		SID:                sid,
		DigestAlgorithm:    digestAlgorithm,
		SignedAttrs:        nil,
		SignatureAlgorithm: signatureAlgorithm,
		Signature:          nil,
		UnsignedAttrs:      nil,
	}

	// Get the message
	content, err := sd.EncapContentInfo.EContentValue()
	if err != nil {
		return err
	}
	if content == nil {
		return errors.New("already detached")
	}
	si.DigestAlgorithm.Parameters.Tag = 5
	si.SignatureAlgorithm.Parameters.Tag = 5

	md := hashFunc.New()
	if _, err = md.Write(content); err != nil {
		return err
	}
	var utcTime time.Time
	if t == "" {
		tim := time.Now()
		utcTime = tim.In(time.FixedZone("KST", 9*60*60)).UTC()
	} else {
		ti, err := strconv.Atoi(t)
		if err != nil {
			return err
		}
		tim := time.Unix(int64(ti), 0)
		if err != nil {
			return err
		}
		//utcTime = utcTime.In(time.FixedZone("KST",9*60*60))
		utcTime = tim.UTC()
	}

	// Build our SignedAttributes
	stAttr, err := NewAttribute(oid.AttributeSigningTime, utcTime)
	if err != nil {
		return err
	}
	mdAttr, err := NewAttribute(oid.AttributeMessageDigest, md.Sum(nil))
	if err != nil {
		return err
	}
	ctAttr, err := NewAttribute(oid.AttributeContentType, sd.EncapContentInfo.EContentType)
	if err != nil {
		return err
	}

	si.SignedAttrs = append(si.SignedAttrs, ctAttr, stAttr, mdAttr)

	// Signature is over the marshaled signed attributes
	sm, err := si.SignedAttrs.MarshaledForSigning()
	if err != nil {
		return err
	}
	smd := hashFunc.New()
	if _, errr := smd.Write(sm); errr != nil {
		return errr
	}

	if si.Signature, err = signer.Sign(rand.Reader, smd.Sum(nil), hashFunc); err != nil {
		return err
	}
	sd.addDigestAlgorithm(si.DigestAlgorithm)
	sd.SignerInfos = append(sd.SignerInfos, si)

	return nil
}
