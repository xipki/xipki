// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.mgmt;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.ctrl.CertLevel;
import org.xipki.ca.api.profile.ctrl.SubjectInfo;
import org.xipki.ca.server.CaUtil;
import org.xipki.ca.server.IdentifiedCertprofile;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.exception.BadCertTemplateException;
import org.xipki.security.exception.ErrorCode;
import org.xipki.security.exception.OperationException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.sign.ConcurrentSigner;
import org.xipki.security.sign.Signer;
import org.xipki.security.sign.SignerConf;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.exception.CertprofileException;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.type.Validity;
import org.xipki.util.misc.StringUtil;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Self-signed certificate builder.
 *
 * @author Lijun Liao
 */

public class SelfSignedCertBuilder {

  private static final Logger LOG =
      LoggerFactory.getLogger(SelfSignedCertBuilder.class);

  private SelfSignedCertBuilder() {
  }

  public static X509Cert generateSelfSigned(
      SecurityFactory securityFactory, String signerType, String signerConf,
      IdentifiedCertprofile certprofile, String subject, String serialNumber,
      Instant notBefore, Instant notAfter)
      throws OperationException, InvalidConfException {
    Args.notNull(securityFactory, "securityFactory");
    Args.notBlank(signerType, "signerType");
    Args.notBlank(subject, "subject");

    BigInteger serialOfThisCert = serialNumber == null || serialNumber.isEmpty()
        ? BigInteger.ONE : StringUtil.toBigInt(serialNumber);
    if (serialOfThisCert.signum() != 1) {
      throw new IllegalArgumentException(
          "serialNumber may not be non-positive: " + serialNumber);
    }

    CertLevel level = Args.notNull(certprofile, "certprofile").certLevel();
    if (CertLevel.RootCA != level) {
      throw new IllegalArgumentException("certprofile is not of level "
          + CertLevel.RootCA);
    }

    if (StringUtil.orEqualsIgnoreCase(signerType, "PKCS12", "JCEKS")) {
      ConfPairs keyValues = new ConfPairs(signerConf);
      Optional.ofNullable(keyValues.value("keystore")).orElseThrow(() ->
          new InvalidConfException("required parameter 'keystore' for types " +
              "PKCS12 and JCEKS, is not specified"));
    }

    ConcurrentSigner signer;
    try {
      List<CaEntry.CaSignerConf> signerConfs =
          CaEntry.splitCaSignerConfs(signerConf);
      List<SignAlgo> restrictedSigAlgos = certprofile.signatureAlgorithms();

      String thisSignerConf = null;
      if (CollectionUtil.isEmpty(restrictedSigAlgos)) {
        thisSignerConf = signerConfs.get(0).conf();
      } else {
        for (SignAlgo algo : restrictedSigAlgos) {
          for (CaEntry.CaSignerConf m : signerConfs) {
            if (m.algo() == algo) {
              thisSignerConf = m.conf();
              break;
            }
          }

          if (thisSignerConf != null) {
            break;
          }
        }
      }

      if (thisSignerConf == null) {
        throw new OperationException(ErrorCode.SYSTEM_FAILURE, "CA does not " +
            "support any signature algorithm restricted by the cert profile");
      }

      signer = securityFactory.createSigner(signerType,
                new SignerConf(thisSignerConf), (X509Cert[]) null);
    } catch (XiSecurityException | ObjectCreationException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
    }

    return generateCertificate(signer, certprofile, subject,
        serialOfThisCert, notBefore, notAfter);
  }

  private static X509Cert generateCertificate(
      ConcurrentSigner signer, IdentifiedCertprofile certprofile,
      String subject, BigInteger serialNumber, Instant notBefore,
      Instant notAfter)
      throws OperationException {
    SubjectPublicKeyInfo publicKeyInfo;

    try {
      SubjectPublicKeyInfo x509PkInfo = KeyUtil.createSubjectPublicKeyInfo(
          signer.getPublicKey());
      publicKeyInfo = X509Util.toRfc3279Style(x509PkInfo);
    } catch (InvalidKeyException ex) {
      LOG.warn("building SubjectPublicKeyInfo from JCE public key", ex);
      throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
    }

    try {
      certprofile.checkPublicKey(publicKeyInfo);
    } catch (CertprofileException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE,
          "exception in cert profile " + certprofile.ident());
    } catch (BadCertTemplateException ex) {
      LOG.warn("certprofile.checkPublicKey", ex);
      throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, ex);
    }

    X500Name requestedSubject = new X500Name(subject);

    SubjectInfo subjectInfo;
    // subject
    try {
      subjectInfo = certprofile.getSubject(requestedSubject);
    } catch (CertprofileException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE,
          "exception in cert profile " + certprofile.ident());
    } catch (BadCertTemplateException ex) {
      LOG.warn("certprofile.getSubject", ex);
      throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, ex);
    }

    notBefore = certprofile.getNotBefore(notBefore);
    if (notBefore == null) {
      notBefore = Instant.now();
    }

    Validity validity = Optional.ofNullable(certprofile.validity())
        .orElseThrow(() -> new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
            "no validity specified in the profile " + certprofile.ident()));

    Instant maxNotAfter = validity.add(notBefore);
    if (notAfter == null) {
      notAfter = maxNotAfter;
    } else if (notAfter.isAfter(maxNotAfter)) {
      notAfter = maxNotAfter;
    }

    X500Name grantedSubject = subjectInfo.grantedSubject();

    try {
      byte[] ski = certprofile.getSubjectKeyIdentifier(publicKeyInfo);
      PublicCaInfo publicCaInfo = new PublicCaInfo(grantedSubject,
          grantedSubject, serialNumber, null, ski, null, null);

      Signer signer0 = signer.borrowSigner();

      ExtensionValues extensionTuples = certprofile.getExtensions(
          requestedSubject, grantedSubject, null, publicKeyInfo,
          publicCaInfo, null, notBefore, notAfter);

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
            grantedSubject, serialNumber,
            Date.from(notBefore), Date.from(notAfter), grantedSubject,
            publicKeyInfo);

      CaUtil.addExtensions(extensionTuples, certBuilder,
          certprofile.extensionControls());
      X509CertificateHolder certHolder;
      try {
        certHolder = certBuilder.build(signer0.x509Signer());
      } finally {
        signer.requiteSigner(signer0);
      }
      return new X509Cert(certHolder);
    } catch (BadCertTemplateException ex) {
      throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, ex);
    } catch (Exception ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
    }
  } // method generateCertificate

}
