// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.scep.util;

import org.xipki.asn1.cms.CertificateChoice;
import org.xipki.asn1.cms.RevocationInfoChoice;
import org.xipki.asn1.cms.SignedData;
import org.xipki.asn1.x509.Certificate;
import org.xipki.asn1.x509.CertificateList;
import org.xipki.codec.asn1.AbstractAsn1Time;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.cms.CmsSignedData;
import org.xipki.pkix.cms.CmsSigner;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.verify.SignatureContentVerifierProvider;
import org.xipki.util.exception.PkixException;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * SCEP Util.
 *
 * @author Lijun Liao (xipki)
 */
public class ScepUtil {

  public static final String CT_X509_NEXT_CA_CERT = "application/x-x509-next-ca-cert";
  public static final String CT_X509_CA_CERT      = "application/x-x509-ca-cert";
  public static final String CT_X509_CA_RA_CERT   = "application/x-x509-ca-ra-cert";
  public static final String CT_PKI_MESSAGE       = "application/x-pki-message";
  public static final String CT_TEXT_PLAIN        = "text/plain";

  private ScepUtil() {
  }

  /*
   * The first one is a non-CA certificate if there exists one non-CA
   * certificate.
   */
  public static List<X509Cert> getCertsFromSignedData(SignedData signedData)
      throws CertificateException {
    Args.notNull(signedData, "signedData");
    CertificateChoice.Set0 set = signedData.getCertificates();
    if (set == null) {
      return Collections.emptyList();
    }

    final int n = set.size();
    if (n == 0) {
      return Collections.emptyList();
    }

    List<X509Cert> certs = new LinkedList<>();

    X509Cert eeCert = null;
    for (int i = 0; i < n; i++) {
      CertificateChoice choice = set.get(i);
      if (choice.hasV3Cert()) {
        X509Cert cert;
        try {
          cert = new X509Cert(choice.getCertificate());
        } catch (CodecException ex) {
          throw new CertificateException(ex);
        }

        if (eeCert == null && cert.basicConstraints() == -1) {
          eeCert = cert;
        } else {
          certs.add(cert);
        }
      }
    }

    if (eeCert != null) {
      certs.add(0, eeCert);
    }

    return certs;
  } // method getCertsFromSignedData

  public static CertificateList getCrlFromPkiMessage(SignedData signedData) {
    RevocationInfoChoice.Set0 set = Args.notNull(signedData, "signedData").getCRLs();
    if (set == null || set.isEmpty()) {
      return null;
    }

    for (RevocationInfoChoice choice : set) {
      CertificateList crl = choice.getCrl();
      if (crl != null) {
        return crl;
      }
    }

    return null;
  } // method getCrlFromPkiMessage

  /**
   * Returns the only signer of the SignedData.
   * @param signedData the SignedData.
   * @return the only signer.
   * @throws CodecException if there is not exactly one signer.
   */
  public static CmsSigner getOnlySigner(CmsSignedData signedData) throws CodecException {
    List<CmsSigner> signers = Args.notNull(signedData, "signedData").getSigners();
    if (signers.size() != 1) {
      throw new CodecException("number of signerInfos is not 1, but " + signers.size());
    }
    return signers.get(0);
  }

  /**
   * Returns the certificate of the signer. It is searched in the given certificates first,
   * and then in the certificates embedded in the SignedData.
   * @param signedData the SignedData.
   * @param signer the signer.
   * @param certs the certificates, may be {@code null}.
   * @return the certificate of the signer.
   * @throws CodecException if not exactly one certificate is found.
   */
  public static Certificate getSignerCert(
      CmsSignedData signedData, CmsSigner signer, List<Certificate> certs) throws CodecException {
    List<Certificate> matches = matchedCerts(signer, certs);
    if (matches.isEmpty()) {
      matches = matchedCerts(signer, signedData.getCertificates());
    }

    if (matches.size() != 1) {
      throw new CodecException("could not find embedded certificate to verify the signature");
    }
    return matches.get(0);
  }

  private static List<Certificate> matchedCerts(CmsSigner signer, List<Certificate> certs) {
    List<Certificate> matches = new LinkedList<>();
    if (certs != null) {
      for (Certificate cert : certs) {
        if (signer.matches(cert)) {
          matches.add(cert);
        }
      }
    }
    return matches;
  }

  /**
   * Verifies the signature of the signer with the certificate.
   * @param signer the signer.
   * @param signerCert the certificate of the signer.
   * @return true if the signature is valid, false otherwise.
   * @throws PkixException if the signature cannot be verified.
   */
  public static boolean verifySignature(CmsSigner signer, X509Cert signerCert)
      throws PkixException {
    return signer.verify(new SignatureContentVerifierProvider(
        signerCert.publicKey(), signerCert.getCert()));
  }

  public static void addCmsCertSet(CmsSignedData.Builder builder, X509Cert[] cmsCertSet) {
    if (cmsCertSet == null || cmsCertSet.length == 0) {
      return;
    }
    Args.notNull(builder, "builder");
    for (X509Cert m : cmsCertSet) {
      builder.addCertificate(m.getCert());
    }
  } // method addCmsCertSet

  /**
   * Returns the digest algorithm of the CMS signer for the given signature algorithm.
   * @param sigAlgId the signature algorithm.
   * @return the digest algorithm.
   * @throws CodecException if the signature algorithm is not supported.
   */
  public static AlgorithmIdentifier getDigestAlgorithm(AlgorithmIdentifier sigAlgId)
      throws CodecException {
    try {
      return SignAlgo.getHashAlgo(sigAlgId).algorithmIdentifier();
    } catch (NoSuchAlgorithmException ex) {
      throw new CodecException(ex.getMessage(), ex);
    }
  }

  public static Instant getTime(AbstractAsn1Time obj) {
    return obj.getTime();
  } // method getTime

}
