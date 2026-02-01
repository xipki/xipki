// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.serveremulator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.exception.ErrorCode;
import org.xipki.security.exception.OperationException;
import org.xipki.security.scep.message.CaCaps;
import org.xipki.security.scep.message.DecodedPkiMessage;
import org.xipki.security.scep.message.EnvelopedDataDecryptor;
import org.xipki.security.scep.message.EnvelopedDataDecryptor.EnvelopedDataDecryptorInstance;
import org.xipki.security.scep.message.IssuerAndSubject;
import org.xipki.security.scep.message.NextCaMessage;
import org.xipki.security.scep.message.PkiMessage;
import org.xipki.security.scep.transaction.CaCapability;
import org.xipki.security.scep.transaction.FailInfo;
import org.xipki.security.scep.transaction.MessageType;
import org.xipki.security.scep.transaction.Nonce;
import org.xipki.security.scep.transaction.PkiStatus;
import org.xipki.security.scep.transaction.TransactionId;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;

/**
 * SCEP responder.
 *
 * @author Lijun Liao (xipki)
 */

public class SimulatorScepResponder {

  private static final Logger LOG =
      LoggerFactory.getLogger(SimulatorScepResponder.class);

  // 5 minutes
  private static final long DFLT_MAX_SIGNINGTIME_BIAS = 5L * 60 * 1000;

  private final CaCaps caCaps;

  private final CaEmulator caEmulator;

  private final RaEmulator raEmulator;

  private final NextCaAndRa nextCaAndRa;

  private final ScepControl control;

  private long maxSigningTimeBiasInMs = DFLT_MAX_SIGNINGTIME_BIAS;

  public SimulatorScepResponder(
      CaCaps caCaps, CaEmulator caEmulator, RaEmulator raEmulator,
      NextCaAndRa nextCaAndRa, ScepControl control) {
    this.caCaps = Args.notNull(caCaps, "caCaps");
    this.caEmulator = Args.notNull(caEmulator, "caEmulator");
    this.control = Args.notNull(control, "control");

    this.raEmulator = raEmulator;
    this.nextCaAndRa = nextCaAndRa;
    if (nextCaAndRa == null) {
      caCaps.removeCapabilities(CaCapability.GetNextCACert);
    } else {
      caCaps.addCapabilities(CaCapability.GetNextCACert);
    }
  }

  /**
   * Set the maximal allowed bias of signing time during the signature
   * verification.
   *
   * @param ms signing time bias in milliseconds. non-positive value deactivate
   *        the check of signing time.
   */
  public void setMaxSigningTimeBias(long ms) {
    this.maxSigningTimeBiasInMs = ms;
  }

  public ContentInfo servicePkiOperation(CMSSignedData requestContent)
      throws CodecException, CaException, NoSuchAlgorithmException {
    Args.notNull(requestContent, "requestContent");
    PrivateKey recipientKey = (raEmulator != null) ? raEmulator.raKey()
        : caEmulator.caKey();
    X509Cert recipientCert = (raEmulator != null) ? raEmulator.raCert()
        : caEmulator.caCert();

    EnvelopedDataDecryptorInstance decInstance =
        new EnvelopedDataDecryptorInstance(recipientCert, recipientKey);
    EnvelopedDataDecryptor recipient = new EnvelopedDataDecryptor(decInstance);

    DecodedPkiMessage req = DecodedPkiMessage.decode(requestContent, recipient,
        null);

    PkiMessage rep = servicePkiOperation0(req);

    SignerConf conf = new SignerConf();
    conf.setHash(req.digestAlgorithm());
    SignAlgo signatureAlgorithm = SignAlgo.getInstance(signingKey(), conf);

    try {
      X509Cert jceSignerCert = signingCert();
      X509Cert[] certs = control.isSendSignerCert()
          ? new X509Cert[]{jceSignerCert} : null;

      return rep.encode(signingKey(), signatureAlgorithm, jceSignerCert,
          certs, req.signatureCert(), req.contentEncryptionAlgorithm());
    } catch (Exception ex) {
      throw new CaException(ex);
    }
  } // method servicePkiOperation

  public ContentInfo encode(NextCaMessage nextCaMsg) throws CaException {
    Args.notNull(nextCaMsg, "nextCaMsg");
    try {
      X509Cert jceSignerCert = signingCert();
      X509Cert[] certs = control.isSendSignerCert()
          ? new X509Cert[]{jceSignerCert} : null;
      return nextCaMsg.encode(signingKey(), jceSignerCert, certs);
    } catch (Exception ex) {
      throw new CaException(ex);
    }
  }

  private PkiMessage servicePkiOperation0(DecodedPkiMessage req)
      throws CaException {
    TransactionId tid = req.transactionId();
    PkiMessage rep = new PkiMessage(tid, MessageType.CertRep,
        Nonce.randomNonce());
    rep.setPkiStatus(PkiStatus.SUCCESS);
    rep.setRecipientNonce(req.senderNonce());

    if (req.failureMessage() != null) {
      return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badRequest);
    }

    Boolean bo = req.isSignatureValid();
    if (bo != null && !bo) {
      return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badMessageCheck);
    }

    bo = req.isDecryptionSuccessful();
    if (bo != null && !bo) {
      return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badRequest);
    }

    Instant signingTime = req.signingTime();
    if (maxSigningTimeBiasInMs > 0) {
      boolean isTimeBad = signingTime == null
          || Math.abs(Duration.between(signingTime, Instant.now()).toMillis())
                > maxSigningTimeBiasInMs;

      if (isTimeBad) {
        return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badTime);
      }
    }

    // check the digest algorithm
    HashAlgo hashAlgo = req.digestAlgorithm();

    boolean supported = false;
    if (hashAlgo == HashAlgo.SHA1) {
      if (caCaps.supportsSHA1()) {
        supported = true;
      }
    } else if (hashAlgo == HashAlgo.SHA256) {
      if (caCaps.supportsSHA256()) {
        supported = true;
      }
    } else if (hashAlgo == HashAlgo.SHA512) {
      if (caCaps.supportsSHA512()) {
        supported = true;
      }
    }

    if (!supported) {
      LOG.warn("tid={}: unsupported digest algorithm {}", tid, hashAlgo);
      return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badAlg);
    } // end if

    // check the content encryption algorithm
    ASN1ObjectIdentifier encOid = req.contentEncryptionAlgorithm();
    if (CMSAlgorithm.DES_EDE3_CBC.equals(encOid)) {
      if (!caCaps.supportsDES3()) {
        LOG.warn("tid={}: encryption with DES3 algorithm {} is not permitted",
            tid, encOid);
        return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badAlg);
      }
    } else if (CMSAlgorithm.AES128_CBC.equals(encOid)) {
      if (!caCaps.supportsAES()) {
        LOG.warn("tid={}: encryption with AES algorithm {} is not permitted",
            tid, encOid);
        return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badAlg);
      }
    } else {
      LOG.warn("tid={}: encryption with algorithm {} is not permitted",
          tid, encOid);
      return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badAlg);
    }

    if (rep.pkiStatus() == PkiStatus.FAILURE) {
      return rep;
    }

    MessageType messageType = req.messageType();

    switch (messageType) {
      case PKCSReq: {
        boolean selfSigned = req.signatureCert().isSelfSigned();

        CertificationRequest csr;
        try {
          csr = parseCsrInRequest(req.messageData());
        } catch (Exception ex) {
          LOG.warn("tid=" + tid + ": invalid CSR", ex);
          return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badRequest);
        }

        if (selfSigned) {
          X500Name name = req.signatureCert().subject();
          if (!name.equals(csr.getCertificationRequestInfo().getSubject())) {
            LOG.warn("tid={}: self-signed cert.subject != CSR.subject", tid);
            return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badRequest);
          }
        }

        String challengePwd = X509Util.getChallengePassword(
            csr.getCertificationRequestInfo());
        if (!control.secret().equals(challengePwd)) {
          LOG.warn("challengePassword is not trusted");
          return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badRequest);
        }

        X509Cert cert;
        try {
          cert = caEmulator.generateCert(csr);
        } catch (Exception ex) {
          throw new CaException("system failure: " + ex.getMessage(), ex);
        }

        if (cert != null && control.isPendingCert()) {
          rep.setPkiStatus(PkiStatus.PENDING);
        } else if (cert != null) {
          ContentInfo messageData = createSignedData(cert);
          rep.setMessageData(messageData);
        } else {
          buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badCertId);
        }

        return rep;
      }
      case CertPoll: {
        IssuerAndSubject is =
            IssuerAndSubject.getInstance(req.messageData());
        X509Cert cert = caEmulator.pollCert(is.issuer(), is.subject());
        if (cert != null) {
          rep.setMessageData(createSignedData(cert));
        } else {
          buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badCertId);
        }

        return rep;
      }
      case GetCert: {
        IssuerAndSerialNumber isn =
            IssuerAndSerialNumber.getInstance(req.messageData());
        X509Cert cert = caEmulator.getCert(isn.getName(),
            isn.getSerialNumber().getValue());
        if (cert != null) {
          rep.setMessageData(createSignedData(cert));
        } else {
          buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badCertId);
        }
        return rep;
      }
      case RenewalReq: {
        if (!caCaps.supportsRenewal()) {
          buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badRequest);
          return rep;
        }

        CertificationRequest csr;
        try {
          csr = parseCsrInRequest(req.messageData());
        } catch (OperationException e) {
          buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badRequest);
          return rep;
        }

        X509Cert cert;
        try {
          cert = caEmulator.generateCert(csr);
        } catch (Exception ex) {
          throw new CaException("system failure: " + ex.getMessage(), ex);
        }

        if (cert != null) {
          rep.setMessageData(createSignedData(cert));
        } else {
          rep.setPkiStatus(PkiStatus.FAILURE);
          rep.setFailInfo(FailInfo.badCertId);
        }
        return rep;
      }
      case GetCRL: {
        IssuerAndSerialNumber isn =
            IssuerAndSerialNumber.getInstance(req.messageData());
        CertificateList crl;
        try {
          crl = caEmulator.getCrl(isn.getName(),
              isn.getSerialNumber().getValue());
        } catch (Exception ex) {
          throw new CaException("system failure: " + ex.getMessage(), ex);
        }

        if (crl != null) {
          rep.setMessageData(createSignedData(crl));
        } else {
          buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badCertId);
        }
        return rep;
      }
      default:
        buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badRequest);
        return rep;
    } // end switch
  } // method servicePkiOperation0

  private ContentInfo createSignedData(CertificateList crl) throws CaException {
    CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
    cmsSignedDataGen.addCRL(new X509CRLHolder(crl));

    CMSSignedData cmsSigneddata;
    try {
      cmsSigneddata = cmsSignedDataGen.generate(new CMSAbsentContent());
    } catch (CMSException ex) {
      throw new CaException(ex.getMessage(), ex);
    }

    return cmsSigneddata.toASN1Structure();
  } // method createSignedData

  private ContentInfo createSignedData(X509Cert cert) throws CaException {
    CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();

    CMSSignedData cmsSigneddata;
    try {
      cmsSignedDataGen.addCertificate(cert.toBcCert());
      if (control.isSendCaCert()) {
        cmsSignedDataGen.addCertificate(caEmulator.caCert().toBcCert());
      }

      cmsSigneddata = cmsSignedDataGen.generate(new CMSAbsentContent());
    } catch (CMSException ex) {
      throw new CaException(ex);
    }

    return cmsSigneddata.toASN1Structure();
  } // method createSignedData

  public PrivateKey signingKey() {
    return (raEmulator != null) ? raEmulator.raKey() : caEmulator.caKey();
  }

  public X509Cert signingCert() {
    return (raEmulator != null) ? raEmulator.raCert()
        : caEmulator.caCert();
  }

  public CaCaps caCaps() {
    return caCaps;
  }

  public CaEmulator caEmulator() {
    return caEmulator;
  }

  public RaEmulator raEmulator() {
    return raEmulator;
  }

  public NextCaAndRa nextCaAndRa() {
    return nextCaAndRa;
  }

  private static PkiMessage buildPkiMessage(
      PkiMessage message, PkiStatus status, FailInfo failInfo) {
    message.setPkiStatus(status);
    message.setFailInfo(failInfo);
    return message;
  }

  private static CertificationRequest parseCsrInRequest(ASN1Encodable p10Asn1)
      throws OperationException {
    try {
      return CertificationRequest.getInstance(p10Asn1);
    } catch (Exception ex) {
      throw new OperationException(ErrorCode.BAD_REQUEST,
          "invalid CSR: " + ex.getMessage());
    }
  }

}
