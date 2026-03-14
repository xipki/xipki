// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkix;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.xipki.security.SignAlgo;
import org.xipki.security.util.Asn1Util;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

/**
 * Wrap a {@link Certificate} to an {@link X509Certificate}.
 *
 * @author Lijun Liao (xipki)
 */
public class JceX509Certificate extends X509Certificate {

  private final Certificate cert;

  private final byte[] encoded;

  private final PublicKey publicKey;

  private final X500Principal issuer;

  private final X500Principal subject;

  private final int version;

  private final int basicConstraints;

  private final boolean[] keyUsage;

  private final Set<String> criticalExtensionOIDs;

  private final Set<String> nonCriticalExtensionOIDs;

  public JceX509Certificate(Certificate cert) throws CertificateEncodingException {
    this.cert = Args.notNull(cert, "cert");
    try {
      TBSCertificate tbs = cert.getTBSCertificate();
      this.version = tbs.getVersion().getValue().intValueExact() + 1;
      this.encoded = cert.getEncoded();
      this.issuer = new X500Principal(tbs.getIssuer().getEncoded());
      this.subject = new X500Principal(tbs.getSubject().getEncoded());

      Extensions extns = tbs.getExtensions();
      this.criticalExtensionOIDs = toTextIdSet(extns.getCriticalExtensionOIDs());
      this.nonCriticalExtensionOIDs = toTextIdSet(extns.getNonCriticalExtensionOIDs());
      this.publicKey = KeyUtil.getPublicKey(cert.getTBSCertificate().getSubjectPublicKeyInfo());
      // basic constraints
      Extension extn = extns.getExtension(Extension.basicConstraints);
      if (extn == null) {
        this.basicConstraints = -1;
      } else {
        BasicConstraints bc = BasicConstraints.getInstance(extn.getParsedValue());
        if (bc.isCA()) {
          BigInteger bn = bc.getPathLenConstraint();
          this.basicConstraints = bn == null ? Integer.MAX_VALUE : bn.intValueExact();
        } else {
          this.basicConstraints = -1;
        }
      }

      // key usage
      extn = extns.getExtension(Extension.keyUsage);
      if (extn == null) {
        keyUsage = null;
      } else {
        DERBitString d = (DERBitString) Asn1Util.toASN1BitString(extn.getParsedValue());
        byte[] bytes = d.getBytes();
        int highestBitNo = Math.min(9, 8 * bytes.length - d.getPadBits());

        keyUsage = new boolean[9];
        for (int i = 0; i < highestBitNo; i++) {
          int b = i < 8 ? 0xFF & bytes[0] : 0xFF & bytes[1];
          int mask = (1 << (7 - (i % 8)));
          keyUsage[i] = (b & mask) != 0;
        }
      }
    } catch (IOException | InvalidKeySpecException e) {
      throw new CertificateEncodingException(e);
    }
  }

  private static Set<String> toTextIdSet(ASN1ObjectIdentifier[] oids) {
    Set<String> set = new HashSet<>();
    if (oids != null) {
      for (ASN1ObjectIdentifier oid : oids) {
        set.add(oid.getId());
      }
    }
    return Collections.unmodifiableSet(set);
  }

  @Override
  public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
    checkValidity(new Date());
  }

  @Override
  public void checkValidity(Date date)
      throws CertificateExpiredException, CertificateNotYetValidException {
    if (date == null) {
      date = new Date();
    }

    if (date.after(getNotAfter())) {
      throw new CertificateExpiredException();
    }

    if (date.before(getNotBefore())) {
      throw new CertificateNotYetValidException();
    }
  }

  @Override
  public int getVersion() {
    return version;
  }

  @Override
  public BigInteger getSerialNumber() {
    return cert.getTBSCertificate().getSerialNumber().getValue();
  }

  @Override
  public Principal getIssuerDN() {
    return issuer;
  }

  @Override
  public Principal getSubjectDN() {
    return subject;
  }

  @Override
  public Date getNotBefore() {
    return cert.getTBSCertificate().getStartDate().getDate();
  }

  @Override
  public Date getNotAfter() {
    return cert.getTBSCertificate().getEndDate().getDate();
  }

  @Override
  public byte[] getTBSCertificate() throws CertificateEncodingException {
    try {
      return cert.getTBSCertificate().getEncoded();
    } catch (IOException e) {
      throw new CertificateEncodingException(e);
    }
  }

  @Override
  public byte[] getSignature() {
    return cert.getSignature().getOctets();
  }

  @Override
  public String getSigAlgName() {
    try {
      return SignAlgo.getInstance(cert.getSignatureAlgorithm()).jceName();
    } catch (NoSuchAlgorithmException e) {
      return "";
    }
  }

  @Override
  public String getSigAlgOID() {
    return cert.getTBSCertificate().getSignature().getAlgorithm().getId();
  }

  @Override
  public byte[] getSigAlgParams() {
    try {
      return cert.getTBSCertificate().getSignature().getParameters().toASN1Primitive().getEncoded();
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public boolean[] getIssuerUniqueID() {
    return null;
  }

  @Override
  public boolean[] getSubjectUniqueID() {
    return null;
  }

  @Override
  public boolean[] getKeyUsage() {
    return keyUsage == null ? null : keyUsage.clone();
  }

  @Override
  public int getBasicConstraints() {
    return basicConstraints;
  }

  @Override
  public byte[] getEncoded() throws CertificateEncodingException {
    return encoded.clone();
  }

  @Override
  public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException,
      InvalidKeyException, NoSuchProviderException, SignatureException {
    verify(key, (Provider) null);
  }

  @Override
  public void verify(PublicKey key, String sigProvider) throws CertificateException,
      NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
    Provider provider = Security.getProvider(sigProvider);
    verify(publicKey, provider);
  }

  @Override
  public String toString() {
    return cert.toString();
  }

  @Override
  public PublicKey getPublicKey() {
    return publicKey;
  }

  @Override
  public boolean hasUnsupportedCriticalExtension() {
    return false;
  }

  @Override
  public Set<String> getCriticalExtensionOIDs() {
    return criticalExtensionOIDs;
  }

  @Override
  public Set<String> getNonCriticalExtensionOIDs() {
    return nonCriticalExtensionOIDs;
  }

  @Override
  public byte[] getExtensionValue(String oid) {
    Extensions extensions = cert.getTBSCertificate().getExtensions();
    Extension extn = extensions.getExtension(new ASN1ObjectIdentifier(oid));
    if (extn == null) {
      return null;
    }

    try {
      return extn.getExtnValue().getEncoded(ASN1Encoding.DER);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public X500Principal getIssuerX500Principal() {
    return issuer;
  }

  @Override
  public X500Principal getSubjectX500Principal() {
    return subject;
  }

}
