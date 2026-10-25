// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ocsp;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.pkix.asn1.ocsp.CertHash;
import org.xipki.pkix.asn1.ocsp.BasicOCSPResponse;
import org.xipki.pkix.asn1.ocsp.CertID;
import org.xipki.pkix.asn1.ocsp.OCSPResponse;
import org.xipki.pkix.asn1.ocsp.OCSPResponseStatus;
import org.xipki.pkix.asn1.ocsp.OcspCertStatus;
import org.xipki.pkix.asn1.ocsp.ResponderID;
import org.xipki.pkix.asn1.ocsp.RevokedInfo;
import org.xipki.pkix.asn1.ocsp.SingleResponse;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.asn1.oid.OcspOIDs;
import org.xipki.pkix.asn1.util.ContentVerifierProvider;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.CRLReason;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.Extension;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.util.Args;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.qa.ValidationIssue;
import org.xipki.qa.ValidationResult;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.pkix.SecurityFactory;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.IssuerHash;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.misc.DateUtil;
import org.xipki.ca.api.TripleState;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * OCSP Qa.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspQa {

  private final SecurityFactory securityFactory;

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  public OcspQa(SecurityFactory securityFactory) {
    this.securityFactory = Args.notNull(securityFactory, "securityFactory");
  }

  public ValidationResult checkOcsp(
      OCSPResponse response, IssuerHash issuerHash, BigInteger serialNumber,
      byte[] encodedCert, QaOcspCertStatus expectedOcspStatus,
      OcspResponseOption responseOption, Instant exptectedRevTime, boolean noSigVerify) {
    List<BigInteger> serialNumbers = new ArrayList<>(1);
    serialNumbers.add(serialNumber);

    Map<BigInteger, byte[]> encodedCerts = null;
    if (encodedCert != null) {
      encodedCerts = new HashMap<>();
      encodedCerts.put(serialNumber, encodedCert);
    }

    Map<BigInteger, QaOcspCertStatus> expectedOcspStatuses = null;
    if (expectedOcspStatus != null) {
      expectedOcspStatuses = new HashMap<>();
      expectedOcspStatuses.put(serialNumber, expectedOcspStatus);
    }

    Map<BigInteger, Instant> exptectedRevTimes = null;
    if (exptectedRevTime != null) {
      exptectedRevTimes = new HashMap<>();
      exptectedRevTimes.put(serialNumber, exptectedRevTime);
    }

    return checkOcsp(response, issuerHash, serialNumbers, encodedCerts,
        expectedOcspStatuses, exptectedRevTimes, responseOption, noSigVerify);
  } // method checkOcsp

  public ValidationResult checkOcsp(OCSPResponse response, OcspError expectedOcspError) {
    Args.notNull(response, "response");
    Args.notNull(expectedOcspError, "expectedOcspError");

    List<ValidationIssue> resultIssues = new LinkedList<>();

    OcspError status = OcspError.forCode(response.getResponseStatus().getValue());

    // Response status
    ValidationIssue issue = new ValidationIssue("OCSP.STATUS", "response.status");
    resultIssues.add(issue);
    if (!status.equals(expectedOcspError)) {
      issue.setFailureMessage("is '" + status.name() +
          "', but expected '" + expectedOcspError.name() + "'");
    }

    return new ValidationResult(resultIssues);
  } // method checkOcsp

  public ValidationResult checkOcsp(
      OCSPResponse response, IssuerHash issuerHash, List<BigInteger> serialNumbers,
      Map<BigInteger, byte[]> encodedCerts,
      Map<BigInteger, QaOcspCertStatus> expectedOcspStatuses,
      Map<BigInteger, Instant> expectedRevTimes,
      OcspResponseOption responseOption, boolean noSigVerify) {
    Args.notNull(response, "response");
    Args.notEmpty(serialNumbers, "serialNumbers");
    Args.notEmpty(expectedOcspStatuses, "expectedOcspStatuses");
    Args.notNull(responseOption, "responseOption");

    List<ValidationIssue> resultIssues = new LinkedList<>();

    OCSPResponseStatus status = response.getResponseStatus();

    // Response status
    ValidationIssue issue = new ValidationIssue("OCSP.STATUS", "response.status");
    resultIssues.add(issue);
    if (!OCSPResponseStatus.SUCCESSFUL.equals(status)) {
      issue.setFailureMessage("is '" + status.getEnumeratedName() +
          "', but expected 'successful'");
      return new ValidationResult(resultIssues);
    }

    ValidationIssue encodingIssue = new ValidationIssue("OCSP.ENCODING", "response encoding");
    resultIssues.add(encodingIssue);

    BasicOCSPResponse basicResp = response.getBasicOCSPResponse();
    if (basicResp == null) {
      encodingIssue.setFailureMessage("The response is not a basicResponse");
      return new ValidationResult(resultIssues);
    }

    SingleResponse.Seq0 singleResponses = basicResp.getResponses();

    issue = new ValidationIssue("OCSP.RESPONSES.NUM", "number of single responses");
    resultIssues.add(issue);

    if (singleResponses == null || singleResponses.isEmpty()) {
      issue.setFailureMessage("received no status from server");
      return new ValidationResult(resultIssues);
    }

    final int n = singleResponses.size();
    if (n != serialNumbers.size()) {
      issue.setFailureMessage("is '" + n + "', but expected '" + serialNumbers.size() + "'");
      return new ValidationResult(resultIssues);
    }

    boolean hasSignature = basicResp.getSignature() != null;

    // check the signature if available
    issue = noSigVerify
        ? new ValidationIssue("OCSP.SIG",
            (hasSignature ? "signature presence (Ignore)" : "signature presence"))
        : new ValidationIssue("OCSP.SIG", "signature presence");

    resultIssues.add(issue);

    if (!hasSignature) {
      issue.setFailureMessage("response is not signed");
    }

    if (hasSignature && !noSigVerify) {
      // signature algorithm
      issue = new ValidationIssue("OCSP.SIG.ALG", "signature algorithm");
      resultIssues.add(issue);

      SignAlgo expectedSigalgo = responseOption.getSignatureAlg();
      if (expectedSigalgo != null) {
        try {
          SignAlgo signAlgo = SignAlgo.getInstance(basicResp.getSignatureAlgorithm());

          if (signAlgo != expectedSigalgo) {
            issue.setFailureMessage("is '" + signAlgo.jceName() +
                "', but expected '" + expectedSigalgo.jceName() + "'");
          }
        } catch (NoSuchAlgorithmException ex) {
          issue.setFailureMessage("could not extract the signature algorithm");
        }
      } // end if (expectedSigalgo != null)

      // signer certificate
      ValidationIssue sigSignerCertIssue = new ValidationIssue(
          "OCSP.SIGNERCERT", "signer certificate");
      resultIssues.add(sigSignerCertIssue);

      // signature validation
      ValidationIssue sigValIssue = new ValidationIssue("OCSP.SIG.VALIDATION",
          "signature validation");
      resultIssues.add(sigValIssue);

      Certificate respSigner = null;

      Certificate.Seq0 responderCerts = basicResp.getCerts();
      if (responderCerts == null || responderCerts.isEmpty()) {
        sigSignerCertIssue.setFailureMessage(
            "no responder certificate is contained in the response");
        sigValIssue.setFailureMessage("could not find certificate to validate signature");
      } else {
        ResponderID respId = basicResp.getResponderID();
        X500Name respIdByName = respId.getByName();
        byte[] respIdByKey = respId.byKey();

        for (Certificate cert : responderCerts) {
          if (respIdByName != null) {
            if (cert.getSubject().equals(respIdByName)) {
              respSigner = cert;
            }
          } else {
            byte[] spkiSha1 = HashAlgo.SHA1.hash(cert.getSubjectPublicKeyInfo().subjectPublicKey());
            if (Arrays.equals(respIdByKey, spkiSha1)) {
              respSigner = cert;
            }
          }

          if (respSigner != null) {
            break;
          }
        }

        if (respSigner == null) {
          sigSignerCertIssue.setFailureMessage("no responder certificate match the ResponderId");
          sigValIssue.setFailureMessage("could not find certificate " +
              "matching the ResponderId to validate signature");
        }
      }

      if (respSigner != null) {
        issue = new ValidationIssue("OCSP.SIGNERCERT.TRUST", "signer certificate validation");
        resultIssues.add(issue);

        for (int i = 0; i < singleResponses.size(); i++) {
          SingleResponse singleResp = singleResponses.get(i);
          if (!respSigner.isValidOn(singleResp.thisUpdate())) {
            issue.setFailureMessage(String.format(
                "responder certificate is not valid on the thisUpdate[%d]: %s",
                i, singleResp.getThisUpdate()));
          }
        } // end for

        X509Cert respIssuer = responseOption.getRespIssuer();
        if (!issue.isFailed() && respIssuer != null) {
          X509Cert jceRespSigner;
          try {
            jceRespSigner = new X509Cert(respSigner);
            if (X509Util.issues(respIssuer, jceRespSigner)) {
              jceRespSigner.verify(respIssuer.publicKey());
            } else {
              issue.setFailureMessage("responder signer is not trusted");
            }
          } catch (Exception ex) {
            issue.setFailureMessage("responder signer is not trusted");
          }
        }

        try {
          PublicKey responderPubKey =
              KeyInfoUtil.getPublicKey(respSigner.getSubjectPublicKeyInfo());

          ContentVerifierProvider cvp = securityFactory.getContentVerifierProvider(responderPubKey);
          if (!basicResp.isSignatureValid(cvp)) {
            sigValIssue.setFailureMessage("signature is invalid");
          }
        } catch (Exception ex) {
          sigValIssue.setFailureMessage("could not validate signature");
        }
      } // end if
    } // end if (hasSignature)

    // nonce
    Extension nonceExtn = basicResp.getExtension(OcspOIDs.id_pkix_ocsp_nonce);
    resultIssues.add(checkOccurrence("OCSP.NONCE", nonceExtn,
        responseOption.getNonceOccurrence()));

    boolean extendedRevoke =
        basicResp.getExtension(ExtensionOIDs.id_pkix_ocsp_extendedRevoke) != null;

    for (int i = 0; i < singleResponses.size(); i++) {
      SingleResponse singleResp = singleResponses.get(i);
      BigInteger serialNumber = singleResp.getCertID().serialNumber();
      QaOcspCertStatus expectedStatus = expectedOcspStatuses.get(serialNumber);
      Instant expectedRevTime = null;
      if (expectedRevTimes != null) {
        expectedRevTime = expectedRevTimes.get(serialNumber);
      }

      byte[] encodedCert = null;
      if (encodedCerts != null) {
        encodedCert = encodedCerts.get(serialNumber);
      }

      List<ValidationIssue> issues = checkSingleCert(i, singleResp,
          issuerHash, expectedStatus, encodedCert, expectedRevTime,
          extendedRevoke, responseOption.getNextUpdateOccurrence(),
          responseOption.getCerthashOccurrence(), responseOption.getCerthashAlg());
      resultIssues.addAll(issues);
    } // end for

    return new ValidationResult(resultIssues);
  } // method checkOcsp

  private List<ValidationIssue> checkSingleCert(
      int index, SingleResponse singleResp, IssuerHash issuerHash,
      QaOcspCertStatus expectedStatus, byte[] encodedCert,
      Instant expectedRevTime, boolean extendedRevoke,
      TripleState nextupdateOccurrence, TripleState certhashOccurrence, HashAlgo certhashAlg) {
    if (expectedStatus == QaOcspCertStatus.unknown
        || expectedStatus == QaOcspCertStatus.issuerUnknown) {
      certhashOccurrence = TripleState.forbidden;
    }

    List<ValidationIssue> issues = new LinkedList<>();

    // issuer hash
    ValidationIssue issue = new ValidationIssue(
        "OCSP.RESPONSE." + index + ".ISSUER", "certificate issuer");
    issues.add(issue);

    CertID certId = singleResp.getCertID();
    AlgorithmIdentifier algId = certId.getHashAlgorithm();
    try {
      HashAlgo hashAlgo = HashAlgo.getInstance(algId);
      if (!issuerHash.match(hashAlgo, certId.issuerNameHash(), certId.issuerKeyHash())) {
        issue.setFailureMessage("issuer not match");
      }
    } catch (NoSuchAlgorithmException ex) {
      issue.setFailureMessage("unknown hash algorithm " + algId.getAlgorithm().getId());
    }

    // status
    issue = new ValidationIssue("OCSP.RESPONSE." + index + ".STATUS", "certificate status");
    issues.add(issue);

    OcspCertStatus singleCertStatus = singleResp.getCertStatus();

    QaOcspCertStatus status = null;
    Long revTimeSec = null;
    if (OcspCertStatus.GOOD.equals(singleCertStatus)) {
      status = QaOcspCertStatus.good;
    } else if (OcspCertStatus.UNKNOWN.equals(singleCertStatus)) {
      status = extendedRevoke ? QaOcspCertStatus.issuerUnknown : QaOcspCertStatus.unknown;
    } else if (singleCertStatus.getRevoked() != null) {
      RevokedInfo revokedInfo = singleCertStatus.getRevoked();
      revTimeSec = revokedInfo.revocationTime().getEpochSecond();

      CRLReason reason = revokedInfo.getRevocationReason();
      if (reason != null) {
        if (extendedRevoke && reason.equals(CRLReason.certificateHold) && revTimeSec == 0) {
          status = QaOcspCertStatus.unknown;
          revTimeSec = null;
        } else {
          CrlReason revocationReason = CrlReason.forReason(reason);
          switch (revocationReason) {
            case UNSPECIFIED:
              status = QaOcspCertStatus.unspecified;
              break;
            case KEY_COMPROMISE:
              status = QaOcspCertStatus.keyCompromise;
              break;
            case CA_COMPROMISE:
              status = QaOcspCertStatus.cACompromise;
              break;
            case AFFILIATION_CHANGED:
              status = QaOcspCertStatus.affiliationChanged;
              break;
            case SUPERSEDED:
              status = QaOcspCertStatus.superseded;
              break;
            case CERTIFICATE_HOLD:
              status = QaOcspCertStatus.certificateHold;
              break;
            case REMOVE_FROM_CRL:
              status = QaOcspCertStatus.removeFromCRL;
              break;
            case PRIVILEGE_WITHDRAWN:
              status = QaOcspCertStatus.privilegeWithdrawn;
              break;
            case AA_COMPROMISE:
              status = QaOcspCertStatus.aACompromise;
              break;
            case CESSATION_OF_OPERATION:
              status = QaOcspCertStatus.cessationOfOperation;
              break;
            default:
              issue.setFailureMessage("should not reach here, unknown " +
                  "CRLReason " + revocationReason);
              break;
          }
        } // end if
      } else {
        status = QaOcspCertStatus.rev_noreason;
      } // end if (revStatus.hasRevocationReason())
    } else {
      issue.setFailureMessage("unknown certstatus: " + singleCertStatus.getClass().getName());
    }

    if (!issue.isFailed() && expectedStatus != status) {
      issue.setFailureMessage("is='" + status + "', but expected='" + expectedStatus + "'");
    }

    // revocation time
    issue = new ValidationIssue("OCSP.RESPONSE." + index + ".REVTIME", "certificate time");
    issues.add(issue);
    if (expectedRevTime != null) {
      if (revTimeSec == null) {
        issue.setFailureMessage("is='null', but expected='" + formatTime(expectedRevTime) + "'");
      } else if (revTimeSec != expectedRevTime.getEpochSecond()) {
        issue.setFailureMessage("is='" + formatTime(Instant.ofEpochSecond(revTimeSec)) +
            "', but expected='" + formatTime(expectedRevTime) + "'");
      }
    }

    // nextUpdate
    Instant nextUpdate = singleResp.nextUpdate();
    issue = checkOccurrence("OCSP.RESPONSE." + index + ".NEXTUPDATE",
        nextUpdate, nextupdateOccurrence);
    issues.add(issue);

    Extension extension = singleResp.getExtension(ExtensionOIDs.isismtt_at_certHash);
    issue = checkOccurrence("OCSP.RESPONSE." + index + ".CERTHASH",
        extension, certhashOccurrence);
    issues.add(issue);

    if (extension != null) {
      CertHash certHash = extension.getCertHash();
      Asn1Oid hashAlgOid = certHash.getHashAlgorithm().getAlgorithm();
      if (certhashAlg != null) {
        // certHash algorithm
        issue = new ValidationIssue("OCSP.RESPONSE." + index + ".CHASH.ALG",
            "certhash algorithm");
        issues.add(issue);

        try {
          HashAlgo is = HashAlgo.getInstance(certHash.getHashAlgorithm());
          if (is != certhashAlg) {
            issue.setFailureMessage("is '" + is + "', but expected '" + certhashAlg + "'");
          }
        } catch (NoSuchAlgorithmException ex) {
          issue.setFailureMessage(ex.getMessage());
        }
      }

      byte[] hashValue = certHash.certificateHash();
      if (encodedCert != null) {
        encodedCert = X509Util.toDerEncoded(encodedCert);

        issue = new ValidationIssue("OCSP.RESPONSE." + index +
            ".CHASH.VALIDITY", "certhash validity");
        issues.add(issue);

        try {
          MessageDigest md = cryptoApi.newMessageDigest(hashAlgOid.getId());
          byte[] expectedHashValue = md.digest(encodedCert);
          if (!Arrays.equals(expectedHashValue, hashValue)) {
            issue.setFailureMessage("certhash does not match the requested certificate");
          }
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
          issue.setFailureMessage("NoSuchAlgorithm " + hashAlgOid.getId());
        }
      } // end if(encodedCert != null)
    } // end if (extension != null)

    return issues;
  } // method checkSingleCert

  private static ValidationIssue checkOccurrence(
      String targetName, Object target, TripleState occurrence) {
    ValidationIssue issue = new ValidationIssue(targetName, targetName);
    if (occurrence == TripleState.forbidden) {
      if (target != null) {
        issue.setFailureMessage("is present, but none is expected");
      }
    } else if (occurrence == TripleState.required) {
      if (target == null) {
        issue.setFailureMessage("is absent, but it is expected");
      }
    }
    return issue;
  } // method checkOccurrence

  private static String formatTime(Instant date) {
    return DateUtil.toUtcTimeyyyyMMddhhmmss(date);
  }
}
