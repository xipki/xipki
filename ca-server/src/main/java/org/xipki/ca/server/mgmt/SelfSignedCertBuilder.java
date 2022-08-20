/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.server.mgmt;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CaEntry.CaSignerConf;
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.server.IdentifiedCertprofile;
import org.xipki.security.*;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.Validity;
import org.xipki.util.exception.BadCertTemplateException;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.exception.ObjectCreationException;
import org.xipki.util.exception.OperationException;
import org.xipki.util.exception.ErrorCode;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.List;

import static org.xipki.util.Args.*;

/**
 * Self-signed certificate builder.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class SelfSignedCertBuilder {

  static class GenerateSelfSignedResult {

    private final String signerConf;

    private final X509Cert cert;

    GenerateSelfSignedResult(String signerConf, X509Cert cert) {
      this.signerConf = signerConf;
      this.cert = cert;
    }

    String getSignerConf() {
      return signerConf;
    }

    X509Cert getCert() {
      return cert;
    }

  } // class GenerateSelfSignedResult

  private static final Logger LOG = LoggerFactory.getLogger(SelfSignedCertBuilder.class);

  private SelfSignedCertBuilder() {
  }

  public static GenerateSelfSignedResult generateSelfSigned(
      SecurityFactory securityFactory,
      String signerType, String signerConf, IdentifiedCertprofile certprofile,
      String subject, BigInteger serialNumber, CaUris caUris, ConfPairs extraControl,
      Date notBefore, Date notAfter)
          throws OperationException, InvalidConfException {
    notNull(securityFactory, "securityFactory");
    notBlank(signerType, "signerType");
    notNull(certprofile, "certprofile");
    notBlank(subject, "subject");
    notNull(serialNumber, "serialNumber");
    if (serialNumber.signum() != 1) {
      throw new IllegalArgumentException(
          "serialNumber may not be non-positive: " + serialNumber);
    }

    Certprofile.CertLevel level = certprofile.getCertLevel();
    if (Certprofile.CertLevel.RootCA != level) {
      throw new IllegalArgumentException(
          "certprofile is not of level " + Certprofile.CertLevel.RootCA);
    }

    if ("PKCS12".equalsIgnoreCase(signerType) || "JCEKS".equalsIgnoreCase(signerType)) {
      ConfPairs keyValues = new ConfPairs(signerConf);
      String keystoreConf = keyValues.value("keystore");
      if (keystoreConf == null) {
        throw new InvalidConfException(
          "required parameter 'keystore' for types PKCS12 and JCEKS, is not specified");
      }
    }

    ConcurrentContentSigner signer;
    try {
      List<CaSignerConf> signerConfs = CaEntry.splitCaSignerConfs(signerConf);
      List<SignAlgo> restrictedSigAlgos = certprofile.getSignatureAlgorithms();

      String thisSignerConf = null;
      if (CollectionUtil.isEmpty(restrictedSigAlgos)) {
        thisSignerConf = signerConfs.get(0).getConf();
      } else {
        for (SignAlgo algo : restrictedSigAlgos) {
          for (CaSignerConf m : signerConfs) {
            if (m.getAlgo() == algo) {
              thisSignerConf = m.getConf();
              break;
            }
          }

          if (thisSignerConf != null) {
            break;
          }
        }
      }

      if (thisSignerConf == null) {
        throw new OperationException(ErrorCode.SYSTEM_FAILURE,
          "CA does not support any signature algorithm restricted by the cert profile");
      }

      signer = securityFactory.createSigner(signerType, new SignerConf(thisSignerConf),
          (X509Cert[]) null);
    } catch (XiSecurityException | ObjectCreationException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
    }

    X509Cert newCert = generateCertificate(signer, certprofile, subject, serialNumber,
        caUris, extraControl, notBefore, notAfter);

    return new GenerateSelfSignedResult(signerConf, newCert);
  } // method generateSelfSigned

  private static X509Cert generateCertificate(ConcurrentContentSigner signer,
      IdentifiedCertprofile certprofile, String subject, BigInteger serialNumber,
      CaUris caUris, ConfPairs extraControl, Date notBefore, Date notAfter)
      throws OperationException {
    SubjectPublicKeyInfo publicKeyInfo;
    try {
      publicKeyInfo = KeyUtil.createSubjectPublicKeyInfo(signer.getPublicKey());
    } catch (InvalidKeyException ex) {
      LOG.warn("KeyUtil.createSubjectPublicKeyInfo", ex);
      throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
    }

    try {
      publicKeyInfo = X509Util.toRfc3279Style(publicKeyInfo);
    } catch (InvalidKeySpecException ex) {
      LOG.warn("SecurityUtil.toRfc3279Style", ex);
      throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, ex);
    }

    PublicKey signerPublicKey = signer.getPublicKey();
    // make sure that the signer's public key is the same the requested one
    PublicKey csrPublicKey;
    try {
      csrPublicKey = KeyUtil.generatePublicKey(publicKeyInfo);
    } catch (InvalidKeySpecException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
    }

    if (!signerPublicKey.equals(csrPublicKey)) {
      throw new OperationException(ErrorCode.BAD_REQUEST,
          "Public keys of the signer's token and of CSR are different");
    }

    try {
      certprofile.checkPublicKey(publicKeyInfo);
    } catch (CertprofileException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE,
          "exception in cert profile " + certprofile.getIdent());
    } catch (BadCertTemplateException ex) {
      LOG.warn("certprofile.checkPublicKey", ex);
      throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, ex);
    }

    X500Name requestedSubject = new X500Name(subject);

    Certprofile.SubjectInfo subjectInfo;
    // subject
    try {
      subjectInfo = certprofile.getSubject(requestedSubject, publicKeyInfo);
    } catch (CertprofileException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE,
          "exception in cert profile " + certprofile.getIdent());
    } catch (BadCertTemplateException ex) {
      LOG.warn("certprofile.getSubject", ex);
      throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, ex);
    }

    notBefore = certprofile.getNotBefore(notBefore);
    if (notBefore == null) {
      notBefore = new Date();
    }

    if (certprofile.hasNoWellDefinedExpirationDate()) {
      if (notAfter == null) {
        notAfter = new Date(253402300799982L); //9999-12-31-23-59-59
      }
    } else {
      Validity validity = certprofile.getValidity();
      if (validity == null) {
        throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
            "no validity specified in the profile " + certprofile.getIdent());
      }

      Date maxNotAfter = validity.add(notBefore);
      if (notAfter == null) {
        notAfter = maxNotAfter;
      } else if (notAfter.after(maxNotAfter)) {
        notAfter = maxNotAfter;
      }
    }

    X500Name grantedSubject = subjectInfo.getGrantedSubject();

    X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(grantedSubject,
        serialNumber, notBefore, notAfter, grantedSubject, publicKeyInfo);

    PublicCaInfo publicCaInfo = new PublicCaInfo(grantedSubject, grantedSubject, serialNumber,
        null, null, caUris, extraControl);

    try {
      addExtensions(certBuilder, certprofile, requestedSubject, grantedSubject, null,
          publicKeyInfo, publicCaInfo, notBefore, notAfter);

      ConcurrentBagEntrySigner signer0 = signer.borrowSigner();
      X509CertificateHolder certHolder;
      try {
        certHolder = certBuilder.build(signer0.value());
      } finally {
        signer.requiteSigner(signer0);
      }
      return new X509Cert(certHolder);
    } catch (BadCertTemplateException ex) {
      throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, ex);
    } catch (NoIdleSignerException | IOException | CertprofileException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
    }
  } // method generateCertificate

  private static void addExtensions(X509v3CertificateBuilder certBuilder,
      IdentifiedCertprofile profile, X500Name requestedSubject, X500Name grantedSubject,
      Extensions extensions, SubjectPublicKeyInfo requestedPublicKeyInfo,
      PublicCaInfo publicCaInfo, Date notBefore, Date notAfter)
      throws CertprofileException, IOException, BadCertTemplateException {
    ExtensionValues extensionTuples = profile.getExtensions(requestedSubject, grantedSubject,
        extensions, requestedPublicKeyInfo, publicCaInfo, null, notBefore, notAfter);

    for (ASN1ObjectIdentifier extType : extensionTuples.getExtensionTypes()) {
      ExtensionValue extValue = extensionTuples.getExtensionValue(extType);
      certBuilder.addExtension(extType, extValue.isCritical(), extValue.getValue());
    }
  } // method addExtensions

}
