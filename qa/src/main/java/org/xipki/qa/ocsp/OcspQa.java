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

package org.xipki.qa.ocsp;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.xipki.ocsp.client.OcspResponseException.Unsuccessful;
import org.xipki.qa.ValidationIssue;
import org.xipki.qa.ValidationResult;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgo;
import org.xipki.security.IssuerHash;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.SecurityFactory;
import org.xipki.security.X509Cert;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.DateUtil;
import org.xipki.util.TripleState;

/**
 * OCSP QA.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspQa {

  private final SecurityFactory securityFactory;

  public OcspQa(SecurityFactory securityFactory) {
    this.securityFactory = Args.notNull(securityFactory, "securityFactory");
  }

  public ValidationResult checkOcsp(OCSPResp response, IssuerHash issuerHash,
      BigInteger serialNumber, byte[] encodedCert,
      OcspCertStatus expectedOcspStatus, OcspResponseOption responseOption,
      Date exptectedRevTime, boolean noSigVerify) {
    List<BigInteger> serialNumbers = new ArrayList<>(1);
    serialNumbers.add(serialNumber);

    Map<BigInteger, byte[]> encodedCerts = null;
    if (encodedCert != null) {
      encodedCerts = new HashMap<>();
      encodedCerts.put(serialNumber, encodedCert);
    }

    Map<BigInteger, OcspCertStatus> expectedOcspStatuses = null;
    if (expectedOcspStatus != null) {
      expectedOcspStatuses = new HashMap<>();
      expectedOcspStatuses.put(serialNumber, expectedOcspStatus);
    }

    Map<BigInteger, Date> exptectedRevTimes = null;
    if (exptectedRevTime != null) {
      exptectedRevTimes = new HashMap<>();
      exptectedRevTimes.put(serialNumber, exptectedRevTime);
    }

    return checkOcsp(response, issuerHash, serialNumbers, encodedCerts,
        expectedOcspStatuses, exptectedRevTimes, responseOption, noSigVerify);
  } // method checkOcsp

  public ValidationResult checkOcsp(OCSPResp response, OcspError expectedOcspError) {
    Args.notNull(response, "response");
    Args.notNull(expectedOcspError, "expectedOcspError");

    List<ValidationIssue> resultIssues = new LinkedList<ValidationIssue>();

    int status = response.getStatus();

    // Response status
    ValidationIssue issue = new ValidationIssue("OCSP.STATUS", "response.status");
    resultIssues.add(issue);
    if (status != expectedOcspError.getStatus()) {
      issue.setFailureMessage("is '" + Unsuccessful.getStatusText(status) + "', but expected '"
          + Unsuccessful.getStatusText(expectedOcspError.getStatus()) + "'");
    }

    return new ValidationResult(resultIssues);
  } // method checkOcsp

  public ValidationResult checkOcsp(OCSPResp response, IssuerHash issuerHash,
      List<BigInteger> serialNumbers, Map<BigInteger, byte[]> encodedCerts,
      Map<BigInteger, OcspCertStatus> expectedOcspStatuses,
      Map<BigInteger, Date> expectedRevTimes, OcspResponseOption responseOption,
      boolean noSigVerify) {
    Args.notNull(response, "response");
    Args.notEmpty(serialNumbers, "serialNumbers");
    Args.notEmpty(expectedOcspStatuses, "expectedOcspStatuses");
    Args.notNull(responseOption, "responseOption");

    List<ValidationIssue> resultIssues = new LinkedList<ValidationIssue>();

    int status = response.getStatus();

    // Response status
    ValidationIssue issue = new ValidationIssue("OCSP.STATUS", "response.status");
    resultIssues.add(issue);
    if (status != 0) {
      issue.setFailureMessage("is '" + Unsuccessful.getStatusText(status)
          + "', but expected 'successful'");
      return new ValidationResult(resultIssues);
    }

    ValidationIssue encodingIssue = new ValidationIssue("OCSP.ENCODING", "response encoding");
    resultIssues.add(encodingIssue);

    BasicOCSPResp basicResp;
    try {
      basicResp = (BasicOCSPResp) response.getResponseObject();
    } catch (OCSPException ex) {
      encodingIssue.setFailureMessage(ex.getMessage());
      return new ValidationResult(resultIssues);
    }

    SingleResp[] singleResponses = basicResp.getResponses();

    issue = new ValidationIssue("OCSP.RESPONSES.NUM", "number of single responses");
    resultIssues.add(issue);

    if (singleResponses == null || singleResponses.length == 0) {
      issue.setFailureMessage("received no status from server");
      return new ValidationResult(resultIssues);
    }

    final int n = singleResponses.length;
    if (n != serialNumbers.size()) {
      issue.setFailureMessage("is '" + n + "', but expected '" + serialNumbers.size() + "'");
      return new ValidationResult(resultIssues);
    }

    boolean hasSignature = basicResp.getSignature() != null;

    // check the signature if available
    if (noSigVerify) {
      issue = new ValidationIssue("OCSP.SIG",
          (hasSignature ? "signature presence (Ignore)" : "signature presence"));
    } else {
      issue = new ValidationIssue("OCSP.SIG", "signature presence");
    }
    resultIssues.add(issue);

    if (!hasSignature) {
      issue.setFailureMessage("response is not signed");
    }

    if (hasSignature & !noSigVerify) {
      // signature algorithm
      issue = new ValidationIssue("OCSP.SIG.ALG", "signature algorithm");
      resultIssues.add(issue);

      String expectedSigalgo = responseOption.getSignatureAlgName();
      if (expectedSigalgo != null) {
        AlgorithmIdentifier sigAlg = basicResp.getSignatureAlgorithmID();
        try {
          String sigAlgName = AlgorithmUtil.getSignatureAlgoName(sigAlg);
          if (!AlgorithmUtil.equalsAlgoName(sigAlgName, expectedSigalgo)) {
            issue.setFailureMessage("is '" + sigAlgName + "', but expected '"
                + expectedSigalgo + "'");
          }
        } catch (NoSuchAlgorithmException ex) {
          issue.setFailureMessage("could not extract the signature algorithm");
        }
      } // end if (expectedSigalgo != null)

      // signer certificate
      ValidationIssue sigSignerCertIssue = new ValidationIssue("OCSP.SIGNERCERT",
          "signer certificate");
      resultIssues.add(sigSignerCertIssue);

      // signature validation
      ValidationIssue sigValIssue = new ValidationIssue("OCSP.SIG.VALIDATION",
          "signature validation");
      resultIssues.add(sigValIssue);

      X509CertificateHolder respSigner = null;

      X509CertificateHolder[] responderCerts = basicResp.getCerts();
      if (responderCerts == null || responderCerts.length < 1) {
        sigSignerCertIssue.setFailureMessage(
            "no responder certificate is contained in the response");
        sigValIssue.setFailureMessage("could not find certificate to validate signature");
      } else {
        ResponderID respId = basicResp.getResponderId().toASN1Primitive();
        X500Name respIdByName = respId.getName();
        byte[] respIdByKey = respId.getKeyHash();

        for (X509CertificateHolder cert : responderCerts) {
          if (respIdByName != null) {
            if (cert.getSubject().equals(respIdByName)) {
              respSigner = cert;
            }
          } else {
            byte[] spkiSha1 = HashAlgo.SHA1.hash(
                cert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
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
          sigValIssue.setFailureMessage("could not find certificate matching the"
              + " ResponderId to validate signature");
        }
      }

      if (respSigner != null) {
        issue = new ValidationIssue("OCSP.SIGNERCERT.TRUST", "signer certificate validation");
        resultIssues.add(issue);

        for (int i = 0; i < singleResponses.length; i++) {
          SingleResp singleResp = singleResponses[i];
          if (!respSigner.isValidOn(singleResp.getThisUpdate())) {
            issue.setFailureMessage(String.format(
                "responder certificate is not valid on the thisUpdate[%d]: %s", i,
                singleResp.getThisUpdate()));
          }
        } // end for

        X509Cert respIssuer = responseOption.getRespIssuer();
        if (!issue.isFailed() && respIssuer != null) {
          X509Cert jceRespSigner;
          try {
            jceRespSigner = new X509Cert(respSigner);
            if (X509Util.issues(respIssuer, jceRespSigner)) {
              jceRespSigner.verify(respIssuer.getPublicKey());
            } else {
              issue.setFailureMessage("responder signer is not trusted");
            }
          } catch (Exception ex) {
            issue.setFailureMessage("responder signer is not trusted");
          }
        }

        try {
          PublicKey responderPubKey = KeyUtil.generatePublicKey(
              respSigner.getSubjectPublicKeyInfo());
          ContentVerifierProvider cvp = securityFactory.getContentVerifierProvider(responderPubKey);
          boolean sigValid = basicResp.isSignatureValid(cvp);
          if (!sigValid) {
            sigValIssue.setFailureMessage("signature is invalid");
          }
        } catch (Exception ex) {
          sigValIssue.setFailureMessage("could not validate signature");
        }
      } // end if
    } // end if (hasSignature)

    // nonce
    Extension nonceExtn = basicResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
    resultIssues.add(checkOccurrence("OCSP.NONCE", nonceExtn, responseOption.getNonceOccurrence()));

    boolean extendedRevoke = basicResp.getExtension(
        ObjectIdentifiers.Extn.id_pkix_ocsp_extendedRevoke) != null;

    for (int i = 0; i < singleResponses.length; i++) {
      SingleResp singleResp = singleResponses[i];
      BigInteger serialNumber = singleResp.getCertID().getSerialNumber();
      OcspCertStatus expectedStatus = expectedOcspStatuses.get(serialNumber);
      Date expectedRevTime = null;
      if (expectedRevTimes != null) {
        expectedRevTime = expectedRevTimes.get(serialNumber);
      }

      byte[] encodedCert = null;
      if (encodedCerts != null) {
        encodedCert = encodedCerts.get(serialNumber);
      }

      List<ValidationIssue> issues = checkSingleCert(i, singleResp, issuerHash, expectedStatus,
          encodedCert, expectedRevTime, extendedRevoke, responseOption.getNextUpdateOccurrence(),
          responseOption.getCerthashOccurrence(), responseOption.getCerthashAlgId());
      resultIssues.addAll(issues);
    } // end for

    return new ValidationResult(resultIssues);
  } // method checkOcsp

  private List<ValidationIssue> checkSingleCert(int index, SingleResp singleResp,
      IssuerHash issuerHash, OcspCertStatus expectedStatus, byte[] encodedCert,
      Date expectedRevTime, boolean extendedRevoke, TripleState nextupdateOccurrence,
      TripleState certhashOccurrence, ASN1ObjectIdentifier certhashAlg) {
    if (expectedStatus == OcspCertStatus.unknown
        || expectedStatus == OcspCertStatus.issuerUnknown) {
      certhashOccurrence = TripleState.forbidden;
    }

    List<ValidationIssue> issues = new LinkedList<>();

    // issuer hash
    ValidationIssue issue = new ValidationIssue("OCSP.RESPONSE." + index + ".ISSUER",
        "certificate issuer");
    issues.add(issue);

    CertificateID certId = singleResp.getCertID();
    HashAlgo hashAlgo = HashAlgo.getInstance(certId.getHashAlgOID());
    if (hashAlgo == null) {
      issue.setFailureMessage("unknown hash algorithm " + certId.getHashAlgOID().getId());
    } else {
      if (!issuerHash.match(hashAlgo, certId.getIssuerNameHash(), certId.getIssuerKeyHash())) {
        issue.setFailureMessage("issuer not match");
      }
    }

    // status
    issue = new ValidationIssue("OCSP.RESPONSE." + index + ".STATUS", "certificate status");
    issues.add(issue);

    CertificateStatus singleCertStatus = singleResp.getCertStatus();

    OcspCertStatus status = null;
    Long revTimeSec = null;
    if (singleCertStatus == null) {
      status = OcspCertStatus.good;
    } else if (singleCertStatus instanceof RevokedStatus) {
      RevokedStatus revStatus = (RevokedStatus) singleCertStatus;
      revTimeSec = revStatus.getRevocationTime().getTime() / 1000;

      if (revStatus.hasRevocationReason()) {
        int reason = revStatus.getRevocationReason();
        if (extendedRevoke && reason == CrlReason.CERTIFICATE_HOLD.getCode() && revTimeSec == 0) {
          status = OcspCertStatus.unknown;
          revTimeSec = null;
        } else {
          CrlReason revocationReason = CrlReason.forReasonCode(reason);
          switch (revocationReason) {
            case UNSPECIFIED:
              status = OcspCertStatus.unspecified;
              break;
            case KEY_COMPROMISE:
              status = OcspCertStatus.keyCompromise;
              break;
            case CA_COMPROMISE:
              status = OcspCertStatus.cACompromise;
              break;
            case AFFILIATION_CHANGED:
              status = OcspCertStatus.affiliationChanged;
              break;
            case SUPERSEDED:
              status = OcspCertStatus.superseded;
              break;
            case CERTIFICATE_HOLD:
              status = OcspCertStatus.certificateHold;
              break;
            case REMOVE_FROM_CRL:
              status = OcspCertStatus.removeFromCRL;
              break;
            case PRIVILEGE_WITHDRAWN:
              status = OcspCertStatus.privilegeWithdrawn;
              break;
            case AA_COMPROMISE:
              status = OcspCertStatus.aACompromise;
              break;
            case CESSATION_OF_OPERATION:
              status = OcspCertStatus.cessationOfOperation;
              break;
            default:
              issue.setFailureMessage(
                  "should not reach here, unknown CRLReason " + revocationReason);
              break;
          }
        } // end if
      } else {
        status = OcspCertStatus.rev_noreason;
      } // end if (revStatus.hasRevocationReason())
    } else if (singleCertStatus instanceof UnknownStatus) {
      status = extendedRevoke ? OcspCertStatus.issuerUnknown : OcspCertStatus.unknown;
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
      } else if (revTimeSec != expectedRevTime.getTime() / 1000) {
        issue.setFailureMessage("is='" +  formatTime(new Date(revTimeSec * 1000))
            + "', but expected='" + formatTime(expectedRevTime) + "'");
      }
    }

    // nextUpdate
    Date nextUpdate = singleResp.getNextUpdate();
    issue = checkOccurrence("OCSP.RESPONSE." + index + ".NEXTUPDATE",
        nextUpdate, nextupdateOccurrence);
    issues.add(issue);

    Extension extension = singleResp.getExtension(ISISMTTObjectIdentifiers.id_isismtt_at_certHash);
    issue = checkOccurrence("OCSP.RESPONSE." + index + ".CERTHASH", extension, certhashOccurrence);
    issues.add(issue);

    if (extension != null) {
      ASN1Encodable extensionValue = extension.getParsedValue();
      CertHash certHash = CertHash.getInstance(extensionValue);
      ASN1ObjectIdentifier hashAlgOid = certHash.getHashAlgorithm().getAlgorithm();
      if (certhashAlg != null) {
        // certHash algorithm
        issue = new ValidationIssue("OCSP.RESPONSE." + index + ".CHASH.ALG", "certhash algorithm");
        issues.add(issue);

        ASN1ObjectIdentifier is = certHash.getHashAlgorithm().getAlgorithm();
        if (!certhashAlg.equals(is)) {
          issue.setFailureMessage("is '" + is.getId() + "', but expected '" + certhashAlg.getId()
              + "'");
        }
      }

      byte[] hashValue = certHash.getCertificateHash();
      if (encodedCert != null) {
        encodedCert = X509Util.toDerEncoded(encodedCert);

        issue = new ValidationIssue("OCSP.RESPONSE." + index + ".CHASH.VALIDITY",
            "certhash validity");
        issues.add(issue);

        try {
          MessageDigest md = MessageDigest.getInstance(hashAlgOid.getId());
          byte[] expectedHashValue = md.digest(encodedCert);
          if (!Arrays.equals(expectedHashValue, hashValue)) {
            issue.setFailureMessage("certhash does not match the requested certificate");
          }
        } catch (NoSuchAlgorithmException ex) {
          issue.setFailureMessage("NoSuchAlgorithm " + hashAlgOid.getId());
        }
      } // end if(encodedCert != null)
    } // end if (extension != null)

    return issues;
  } // method checkSingleCert

  private static ValidationIssue checkOccurrence(String targetName, Object target,
      TripleState occurrence) {
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

  private static final String formatTime(Date date) {
    return DateUtil.toUtcTimeyyyyMMddhhmmss(date);
  }
}
