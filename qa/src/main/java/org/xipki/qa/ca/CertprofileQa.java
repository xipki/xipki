// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.profile.Certprofile.X509CertVersion;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.conf.X509ProfileType;
import org.xipki.qa.ValidationIssue;
import org.xipki.qa.ValidationResult;
import org.xipki.qa.ca.extn.ExtensionsChecker;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.Validity;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.LinkedList;
import java.util.List;

/**
 * QA for Certprofile.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CertprofileQa {

  private static final Logger LOG = LoggerFactory.getLogger(CertprofileQa.class);

  private static final Instant MAX_CERT_TIME = ZonedDateTime.of(9999, 12, 31,
      23, 59, 59, 0, ZoneOffset.UTC).toInstant(); //9999-12-31T23:59:59.000

  private static final Instant EPOCHTIME_2050010100 = ZonedDateTime.of(2050, 1, 1,
      0, 0, 0, 0, ZoneOffset.UTC).toInstant();
  //2050-01-01T00:00:00.000;

  private final SubjectChecker subjectChecker;

  private final PublicKeyChecker publicKeyChecker;

  private final ExtensionsChecker extensionsChecker;

  private final XijsonCertprofile certprofile;

  public CertprofileQa(String data) throws CertprofileException {
    this(StringUtil.toUtf8Bytes(Args.notNull(data, "data")));
  }

  public CertprofileQa(byte[] dataBytes) throws CertprofileException {
    Args.notNull(dataBytes, "dataBytes");
    try {
      X509ProfileType conf = X509ProfileType.parse(dataBytes);
      certprofile = new XijsonCertprofile();
      certprofile.initialize(conf);

      this.publicKeyChecker = new PublicKeyChecker(certprofile.getKeyAlgorithms());
      this.subjectChecker = new SubjectChecker(certprofile.getSubjectControl());
      this.extensionsChecker = new ExtensionsChecker(conf, certprofile);
    } catch (RuntimeException ex) {
      LogUtil.error(LOG, ex);
      throw new CertprofileException("RuntimeException thrown while initializing certprofile: " + ex.getMessage());
    }
  } // constructor

  public ValidationResult checkCert(
      byte[] certBytes, IssuerInfo issuerInfo, X500Name requestedSubject,
      SubjectPublicKeyInfo requestedPublicKey, Extensions requestedExtensions) {
    Args.notNull(certBytes, "certBytes");
    Args.notNull(issuerInfo, "issuerInfo");
    Args.notNull(requestedSubject, "requestedSubject");
    Args.notNull(requestedPublicKey, "requestedPublicKey");

    List<ValidationIssue> resultIssues = new LinkedList<>();

    // certificate size
    ValidationIssue issue = new ValidationIssue("X509.SIZE", "certificate size");
    resultIssues.add(issue);

    certBytes = X509Util.toDerEncoded(certBytes);

    Integer maxSize = certprofile.getMaxSize();
    if (maxSize != 0) {
      int size = certBytes.length;
      if (size > maxSize) {
        issue.setFailureMessage(String.format("certificate exceeds the maximal allowed size: %d > %d", size, maxSize));
      }
    }

    // certificate encoding
    issue = new ValidationIssue("X509.ENCODING", "certificate encoding");
    resultIssues.add(issue);
    Certificate bcCert = Certificate.getInstance(certBytes);
    TBSCertificate tbsCert = bcCert.getTBSCertificate();
    X509Cert cert = new X509Cert(bcCert, certBytes);

    // syntax version
    issue = new ValidationIssue("X509.VERSION", "certificate version");
    resultIssues.add(issue);
    int versionNumber = tbsCert.getVersion().intPositiveValueExact();

    X509CertVersion expVersion = certprofile.getVersion();
    if (versionNumber != expVersion.getVersionNumber()) {
      issue.setFailureMessage("is '" + versionNumber + "' but expected '" + expVersion.getVersionNumber() + "'");
    }

    // serialNumber
    issue = new ValidationIssue("X509.serialNumber", "certificate serial number");
    resultIssues.add(issue);
    BigInteger serialNumber = tbsCert.getSerialNumber().getValue();
    if (serialNumber.signum() != 1) {
      issue.setFailureMessage("not positive");
    } else {
      if (serialNumber.bitLength() >= 160) {
        issue.setFailureMessage("serial number has more than 20 octets");
      }
    }

    // signatureAlgorithm
    List<SignAlgo> signatureAlgorithms = certprofile.getSignatureAlgorithms();
    if (CollectionUtil.isNotEmpty(signatureAlgorithms)) {
      issue = new ValidationIssue("X509.SIGALG", "signature algorithm");
      resultIssues.add(issue);

      AlgorithmIdentifier sigAlgId = bcCert.getSignatureAlgorithm();
      AlgorithmIdentifier tbsSigAlgId = tbsCert.getSignature();
      if (!tbsSigAlgId.equals(sigAlgId)) {
        issue.setFailureMessage("Certificate.tbsCertificate.signature != Certificate.signatureAlgorithm");
      }

      if (!issue.isFailed()) {
        try {
          SignAlgo signAlgo = SignAlgo.getInstance(sigAlgId);

          if (!signatureAlgorithms.contains(signAlgo)) {
            issue.setFailureMessage("signatureAlgorithm '" + signAlgo + "' is not allowed");
          }

          if (!issue.isFailed()) {
            if (!sigAlgId.equals(signAlgo.getAlgorithmIdentifier())) {
              issue.setFailureMessage("signatureAlgorithm has invalid content");
            }
          }
        } catch (NoSuchAlgorithmException ex) {
          issue.setFailureMessage("unsupported signature algorithm " + sigAlgId.getAlgorithm().getId());
        }
      }
    }

    // notBefore encoding
    issue = new ValidationIssue("X509.NOTBEFORE.ENCODING", "notBefore encoding");
    checkTime(tbsCert.getStartDate(), issue);

    // notAfter encoding
    issue = new ValidationIssue("X509.NOTAFTER.ENCODING", "notAfter encoding");
    checkTime(tbsCert.getStartDate(), issue);

    if (certprofile.getNotBeforeOption().getMidNightTimeZone() != null) {
      issue = new ValidationIssue("X509.NOTBEFORE", "notBefore midnight");
      resultIssues.add(issue);
      ZonedDateTime cal = ZonedDateTime.ofInstant(cert.getNotBefore(), ZoneOffset.UTC);

      int minute = cal.getMinute();
      int second = cal.getSecond();

      if (minute != 0 || second != 0) {
        issue.setFailureMessage(" '" + cert.getNotBefore() + "' is not midnight time");
      }
    }

    // validity
    issue = new ValidationIssue("X509.VALIDITY", "cert validity");
    resultIssues.add(issue);

    if (cert.getNotAfter().isBefore(cert.getNotBefore())) {
      issue.setFailureMessage("notAfter may not be before notBefore");
    } else if (cert.getNotBefore().isBefore(issuerInfo.getCaNotBefore())) {
      issue.setFailureMessage("notBefore may not be before CA's notBefore");
    } else {
      if (certprofile.hasNoWellDefinedExpirationDate()) {
        if (MAX_CERT_TIME.getEpochSecond() != cert.getNotAfter().getEpochSecond()) {
          issue.setFailureMessage("cert notAfter != 99991231235959Z");
        }
      } else {
        Validity validity = certprofile.getValidity();
        Instant expectedNotAfter = validity.add(cert.getNotBefore());
        if (expectedNotAfter.isAfter(MAX_CERT_TIME)) {
          expectedNotAfter = MAX_CERT_TIME;
        }

        if (issuerInfo.isCutoffNotAfter() && expectedNotAfter.isAfter(issuerInfo.getCaNotAfter())) {
          expectedNotAfter = issuerInfo.getCaNotAfter();
        }

        if (Math.abs(expectedNotAfter.getEpochSecond() - cert.getNotAfter().getEpochSecond()) > 60) {
          issue.setFailureMessage("cert validity is not within " + validity);
        }
      }
    }

    // subjectPublicKeyInfo
    resultIssues.addAll(publicKeyChecker.checkPublicKey(bcCert.getSubjectPublicKeyInfo(), requestedPublicKey));

    // Signature
    issue = new ValidationIssue("X509.SIG", "whether certificate is signed by CA");
    resultIssues.add(issue);
    try {
      cert.verify(issuerInfo.getCert().getPublicKey(), "BC");
    } catch (NoSuchAlgorithmException ex) {
      try {
        cert.verify(issuerInfo.getCert().getPublicKey());
      } catch (Exception ex1) {
        issue.setFailureMessage("invalid signature");
      }
    } catch (Exception ex) {
      issue.setFailureMessage("invalid signature");
    }

    // issuer
    issue = new ValidationIssue("X509.ISSUER", "certificate issuer");
    resultIssues.add(issue);
    if (!cert.getIssuer().equals(issuerInfo.getCert().getSubject())) {
      issue.setFailureMessage("issue in certificate does not equal the subject of CA certificate");
    }

    // subject
    resultIssues.addAll(subjectChecker.checkSubject(bcCert.getSubject(), requestedSubject));

    // issuerUniqueID
    issue = new ValidationIssue("X509.IssuerUniqueID", "issuerUniqueID");
    resultIssues.add(issue);
    if (tbsCert.getIssuerUniqueId() != null) {
      issue.setFailureMessage("is present but not permitted");
    }

    // subjectUniqueID
    issue = new ValidationIssue("X509.SubjectUniqueID", "subjectUniqueID");
    resultIssues.add(issue);
    if (tbsCert.getSubjectUniqueId() != null) {
      issue.setFailureMessage("is present but not permitted");
    }

    // extensions
    issue = new ValidationIssue("X509.GrantedSubject", "grantedSubject");
    resultIssues.add(issue);

    resultIssues.addAll(extensionsChecker.checkExtensions(bcCert, issuerInfo, requestedExtensions, requestedSubject));

    return new ValidationResult(resultIssues);
  } // method checkCert

  private static void checkTime(Time time, ValidationIssue issue) {
    ASN1Primitive asn1Time = time.toASN1Primitive();
    if (time.getDate().toInstant().isBefore(EPOCHTIME_2050010100)) {
      if (!(asn1Time instanceof ASN1UTCTime)) {
        issue.setFailureMessage("not encoded as UTCTime");
      }
    } else {
      if (!(asn1Time instanceof ASN1GeneralizedTime)) {
        issue.setFailureMessage("not encoded as GeneralizedTime");
      }
    }
  }

}
