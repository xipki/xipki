// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.kpgen.KeypairGenerator;
import org.xipki.ca.api.profile.ctrl.KeypairGenControl;
import org.xipki.ca.api.profile.ctrl.SubjectInfo;
import org.xipki.ca.api.profile.ctrl.ValidityMode;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;
import org.xipki.security.exception.BadCertTemplateException;
import org.xipki.security.exception.ErrorCode;
import org.xipki.security.exception.OperationException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkix.KeyInfoPair;
import org.xipki.security.sign.ConcurrentSigner;
import org.xipki.security.util.X509Util;
import org.xipki.util.extra.exception.CertprofileException;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.type.Validity;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

/**
 * X509CA GrandCertTemplate builder.
 *
 * @author Lijun Liao
 */
class GrandCertTemplateBuilder {

  private static final Logger LOG =
      LoggerFactory.getLogger(GrandCertTemplateBuilder.class);

  private static final Instant MAX_CERT_TIME = ZonedDateTime.of(
      9999, 12, 31, 23, 59, 59, 0,
      ZoneOffset.UTC).toInstant(); //9999-12-31T23:59:59.000

  private final KeySpec keyspecByImplicitCA;

  private final CaInfo caInfo;

  GrandCertTemplateBuilder(CaInfo caInfo) {
    this.caInfo = caInfo;
    this.keyspecByImplicitCA = caInfo.caKeySpec();
  }

  X509Ca.GrantedCertTemplate create(
      boolean batch, IdentifiedCertprofile certprofile,
      CertTemplateData certTemplate, List<KeypairGenerator> keypairGenerators)
      throws OperationException {
    if (caInfo.revocationInfo() != null) {
      throw new OperationException(ErrorCode.NOT_PERMITTED, "CA is revoked");
    }

    if (certprofile == null) {
      throw new OperationException(ErrorCode.UNKNOWN_CERT_PROFILE,
          "unknown cert profile " + certTemplate.certprofileName());
    }

    ConcurrentSigner signer = Optional.ofNullable(
            caInfo.getSigner(certprofile.signatureAlgorithms()))
        .orElseThrow(() -> new OperationException(ErrorCode.SYSTEM_FAILURE,
            "CA does not support any signature algorithm restricted by " +
            "the cert profile"));

    final NameId certprofileIdent = certprofile.ident();

    switch (certprofile.certLevel()) {
      case RootCA:
        throw new OperationException(ErrorCode.NOT_PERMITTED,
            "CA is not allowed to generate Root CA certificate");
      case SubCA:
      case CROSS:
        Integer reqPathlen = certprofile.pathLenBasicConstraint();
        int caPathLen = caInfo.pathLenConstraint();
        boolean allowed = (reqPathlen == null && caPathLen == Integer.MAX_VALUE)
                            || (reqPathlen != null && reqPathlen < caPathLen);
        if (!allowed) {
          throw new OperationException(ErrorCode.NOT_PERMITTED,
              "invalid BasicConstraint.pathLenConstraint");
        }
        break;
      default:
    }

    boolean forCrossCert = certTemplate.isForCrossCert();
    X500Name requestedSubject = forCrossCert ? certTemplate.subject()
        : CaUtil.removeEmptyRdns(certTemplate.subject());

    Instant reqNotBefore = certTemplate.notBefore();

    Instant grantedNotBefore = certprofile.getNotBefore(reqNotBefore);
    // notBefore in the past is not permitted (due to the fact that some
    // clients may not have accurate time, we allow max. 5 minutes in the past)
    Instant _10MinBefore = Instant.now().minus(10, ChronoUnit.MINUTES);
    if (grantedNotBefore.isBefore(_10MinBefore)) {
      grantedNotBefore = _10MinBefore;
    }

    if (grantedNotBefore.isAfter(caInfo.noNewCertificateAfter())) {
      throw new OperationException(ErrorCode.NOT_PERMITTED,
          "CA is not permitted to issue certificate after " +
          caInfo.noNewCertificateAfter());
    }

    if (grantedNotBefore.isBefore(caInfo.notBefore())) {
      // notBefore may not be before CA's notBefore
      grantedNotBefore = caInfo.notBefore();
    }

    SubjectPublicKeyInfo grantedPublicKeyInfo = certTemplate.publicKeyInfo();
    PrivateKeyInfo privateKey = null;

    if (grantedPublicKeyInfo != null) {
      grantedPublicKeyInfo = X509Util.toRfc3279Style(grantedPublicKeyInfo);

      BigInteger rsaModulus = null;
      if (grantedPublicKeyInfo.getAlgorithm().getAlgorithm().equals(
          OIDs.Algo.id_rsaEncryption)) {
        try {
          ASN1Sequence seq = ASN1Sequence.getInstance(
              grantedPublicKeyInfo.getPublicKeyData().getBytes());
          rsaModulus = ((ASN1Integer) seq.getObjectAt(0)).getValue();
        } catch (IllegalArgumentException ex) {
          throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
              "invalid format of RSA public key", ex);
        }
      }

      if (rsaModulus != null && RSABrokenKey.isAffected(rsaModulus)) {
        throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
            "RSA public key is too weak");
      }
    } else if (certTemplate.isServerkeygen()) {
      KeypairGenControl kg = certprofile.keypairGenControl();

      if (kg == null || kg.isForbidden()) {
        throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
            "no public key is specified");
      }

      KeySpec keyspec = kg.isInheritCA() ? keyspecByImplicitCA
          : kg.keySpec();

      KeypairGenerator keypairGenerator = null;

      if (keypairGenerators != null) {
        for (KeypairGenerator m : keypairGenerators) {
          if (m.supports(keyspec)) {
            keypairGenerator = m;
            break;
          }
        }
      }

      if (keypairGenerator == null) {
        throw new OperationException(ErrorCode.SYSTEM_FAILURE,
            "found no keypair generator for keyspec " + keyspec);
      }

      String name = keypairGenerator.name();

      try {
        KeyInfoPair keyInfoPair = keypairGenerator.generateKeypair(keyspec);
        privateKey = keyInfoPair.getPrivate();
        grantedPublicKeyInfo = keyInfoPair.getPublic();

        LOG.info("generated keypair {} with generator {}", keyspec, name);
      } catch (XiSecurityException ex) {
        String msg = "error generating keypair " + keyspec +
            " using generator " + name;
        LogUtil.error(LOG, ex, msg);
        throw new OperationException(ErrorCode.SYSTEM_FAILURE, msg);
      }

      // adapt the algorithm identifier in private key and public key
      AlgorithmIdentifier keyAlgId = keyspec.algorithmIdentifier();
      if (!privateKey.getPrivateKeyAlgorithm().equals(keyAlgId)) {
        ASN1BitString asn1PublicKeyData = privateKey.getPublicKeyData();
        try {
          privateKey = new PrivateKeyInfo(
              keyAlgId,
              privateKey.getPrivateKey().toASN1Primitive(),
              privateKey.getAttributes(),
              asn1PublicKeyData == null ? null : asn1PublicKeyData.getOctets());
        } catch (IOException ex) {
          throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
        }
      }

      if (!grantedPublicKeyInfo.getAlgorithm().equals(keyAlgId)) {
        grantedPublicKeyInfo = new SubjectPublicKeyInfo(keyAlgId,
            grantedPublicKeyInfo.getPublicKeyData());
      }
    } else {
      // show not reach here
      throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
          "no public key is specified");
    }

    // public key
    try {
      grantedPublicKeyInfo = certprofile.checkPublicKey(grantedPublicKeyInfo);
    } catch (CertprofileException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE,
          "exception in cert profile " + certprofileIdent);
    } catch (BadCertTemplateException ex) {
      throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, ex);
    }

    StringBuilder msgBuilder = new StringBuilder();

    SubjectInfo subjectInfo;
    try {
      subjectInfo = certprofile.getSubject(requestedSubject);
    } catch (CertprofileException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE,
          "exception in cert profile " + certprofileIdent);
    } catch (BadCertTemplateException ex) {
      throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, ex);
    }

    // subject
    X500Name grantedSubject;
    if (forCrossCert) {
      // For cross certificate, the original requested certificate must be used.
      grantedSubject = requestedSubject;
    } else {
      grantedSubject = subjectInfo.grantedSubject();

      if (subjectInfo.warning() != null) {
        msgBuilder.append(", ").append(subjectInfo.warning());
      }
    }

    // make sure that the grantedSubject does not equal the CA's subject
    if (X509Util.canonicalizeName(grantedSubject).equals(
        caInfo.publicCaInfo().c14nSubject())) {
      throw new OperationException(ErrorCode.ALREADY_ISSUED,
          "certificate with the same subject as CA is not allowed");
    }

    // notAfter
    Instant grantedNotAfter;
    if (certprofile.hasNoWellDefinedExpirationDate()) {
      grantedNotAfter = MAX_CERT_TIME;
    } else {
      Validity validity = certprofile.validity();

      if (validity == null) {
        validity = caInfo.maxValidity();
      } else if (validity.compareTo(caInfo.maxValidity()) > 0) {
        validity = caInfo.maxValidity();
      }

      Instant maxNotAfter = validity.add(grantedNotBefore);
      // maxNotAfter not after 99991231-235959.000
      if (maxNotAfter.isAfter(MAX_CERT_TIME)) {
        maxNotAfter = MAX_CERT_TIME;
      }

      grantedNotAfter = certTemplate.notAfter();

      if (grantedNotAfter != null) {
        if (grantedNotAfter.isAfter(maxNotAfter)) {
          grantedNotAfter = maxNotAfter;
          msgBuilder.append(", notAfter modified");
        }
      } else {
        grantedNotAfter = maxNotAfter;
      }

      if (grantedNotAfter.isAfter(caInfo.notAfter())) {
        ValidityMode caMode = caInfo.validityMode();
        ValidityMode profileMode = certprofile.notAfterMode();
        if (profileMode == null) {
          profileMode = ValidityMode.BY_CA;
        }

        if (profileMode == ValidityMode.STRICT) {
          throw new OperationException(ErrorCode.NOT_PERMITTED,
              "notAfter outside of CA's validity is not permitted by " +
              "the CertProfile");
        }

        if (caMode == ValidityMode.STRICT) {
          throw new OperationException(ErrorCode.NOT_PERMITTED,
              "notAfter outside of CA's validity is not permitted by the CA");
        }

        boolean useCaNotAfter = caMode == ValidityMode.CUTOFF ||
            profileMode == ValidityMode.CUTOFF;

        if (useCaNotAfter) {
          grantedNotAfter = caInfo.notAfter();
        } else {
          throw new IllegalStateException(
              "should not reach here, CA ValidityMode " + caMode +
              " CertProfile NotAfterMode " + profileMode);
        } // end if (caMode)
      } // end if (grantedNotAfter)
    }

    String warning = null;
    if (msgBuilder.length() > 2) {
      warning = msgBuilder.substring(2);
    }
    X509Ca.GrantedCertTemplate gct = new X509Ca.GrantedCertTemplate(batch,
        certTemplate.certReqId(), certTemplate.extensions(), certprofile,
        grantedNotBefore, grantedNotAfter, requestedSubject,
        grantedPublicKeyInfo, privateKey, signer, warning);
    gct.setGrantedSubject(grantedSubject);
    return gct;

  } // method createGrantedCertTemplate

  /**
   * RSA broken key checker.
   */
  private static class RSABrokenKey {

    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger ZERO = BigInteger.ZERO;

    private static final BigInteger[] primes;

    private static final BigInteger[] markers;

    static {
      int[] ints = new int[]{
          3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
          71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
          149, 151, 157, 163, 167};

      primes = new BigInteger[ints.length];
      for (int i = 0; i < ints.length; i++) {
        primes[i] = BigInteger.valueOf(ints[i]);
      }

      String[] strs = new String[]{
          "6", "1e", "7e", "402", "161a", "1a316", "30af2", "7ffffe",
          "1ffffffe", "7ffffffe", "4000402", "1fffffffffe", "7fffffffffe",
          "7ffffffffffe",        "12dd703303aed2",    "7fffffffffffffe",
          "1434026619900b0a",    "7fffffffffffffffe", "1164729716b1d977e",
          "147811a48004962078a", "b4010404000640502", "7fffffffffffffffffffe",
          "1fffffffffffffffffffffe",        "1000000006000001800000002",
          "1ffffffffffffffffffffffffe",     "16380e9115bd964257768fe396",
          "27816ea9821633397be6a897e1a",    "1752639f4e85b003685cbe7192ba",
          "1fffffffffffffffffffffffffffe", "6ca09850c2813205a04c81430a190536",
          "7fffffffffffffffffffffffffffffffe",
          "1fffffffffffffffffffffffffffffffffe",
          "7fffffffffffffffffffffffffffffffffe",
          "1ffffffffffffffffffffffffffffffffffffe",
          "50c018bc00482458dac35b1a2412003d18030a",
          "161fb414d76af63826461899071bd5baca0b7e1a",
          "7fffffffffffffffffffffffffffffffffffffffe",
          "7ffffffffffffffffffffffffffffffffffffffffe"};

      markers = new BigInteger[strs.length];
      for (int i = 0; i < markers.length; i++) {
        markers[i] = new BigInteger(strs[i], 16);
      }
    } // method static

    public static boolean isAffected(BigInteger modulus) {
      for (int i = 0; i < primes.length; i++) {
        BigInteger bi = ONE.shiftLeft(modulus.remainder(primes[i]).intValue());
        if (bi.and(markers[i]).equals(ZERO)) {
          return false;
        }
      }

      return true;
    }
  }
}
