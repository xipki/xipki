/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.scep.serveremulator;

import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.scep.crypto.ScepHashAlgo;
import org.xipki.scep.exception.MessageDecodingException;
import org.xipki.scep.message.CaCaps;
import org.xipki.scep.message.DecodedPkiMessage;
import org.xipki.scep.message.EnvelopedDataDecryptor;
import org.xipki.scep.message.EnvelopedDataDecryptorInstance;
import org.xipki.scep.message.IssuerAndSubject;
import org.xipki.scep.message.NextCaMessage;
import org.xipki.scep.message.PkiMessage;
import org.xipki.scep.serveremulator.AuditEvent.AuditLevel;
import org.xipki.scep.transaction.CaCapability;
import org.xipki.scep.transaction.FailInfo;
import org.xipki.scep.transaction.MessageType;
import org.xipki.scep.transaction.Nonce;
import org.xipki.scep.transaction.PkiStatus;
import org.xipki.scep.transaction.TransactionId;
import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public class ScepResponder {

  private static final Logger LOG = LoggerFactory.getLogger(ScepResponder.class);

  private static final long DFLT_MAX_SIGNINGTIME_BIAS = 5L * 60 * 1000; // 5 minutes

  private static final Set<ASN1ObjectIdentifier> AES_ENC_ALGS =
      new HashSet<ASN1ObjectIdentifier>();

  private final CaCaps caCaps;

  private final CaEmulator caEmulator;

  private final RaEmulator raEmulator;

  private final NextCaAndRa nextCaAndRa;

  private final ScepControl control;

  private long maxSigningTimeBiasInMs = DFLT_MAX_SIGNINGTIME_BIAS;

  static {
    AES_ENC_ALGS.add(CMSAlgorithm.AES128_CBC);
    AES_ENC_ALGS.add(CMSAlgorithm.AES128_CCM);
    AES_ENC_ALGS.add(CMSAlgorithm.AES128_GCM);
    AES_ENC_ALGS.add(CMSAlgorithm.AES192_CBC);
    AES_ENC_ALGS.add(CMSAlgorithm.AES192_CCM);
    AES_ENC_ALGS.add(CMSAlgorithm.AES192_GCM);
    AES_ENC_ALGS.add(CMSAlgorithm.AES256_CBC);
    AES_ENC_ALGS.add(CMSAlgorithm.AES256_CCM);
    AES_ENC_ALGS.add(CMSAlgorithm.AES256_GCM);
  }

  public ScepResponder(CaCaps caCaps, CaEmulator caEmulator, RaEmulator raEmulator,
      NextCaAndRa nextCaAndRa, ScepControl control) throws Exception {
    this.caCaps = ScepUtil.requireNonNull("caCaps", caCaps);
    this.caEmulator = ScepUtil.requireNonNull("caEmulator", caEmulator);
    this.control = ScepUtil.requireNonNull("control", control);

    this.raEmulator = raEmulator;
    this.nextCaAndRa = nextCaAndRa;
    CaCaps caps = caCaps;
    if (nextCaAndRa == null) {
      caps.removeCapabilities(CaCapability.GetNextCACert);
    } else {
      caps.addCapabilities(CaCapability.GetNextCACert);
    }
  }

  /**
   * TODO.
   * @param ms signing time bias in milliseconds. non-positive value deactivate
   *        the check of signing time.
   */
  public void setMaxSigningTimeBias(long ms) {
    this.maxSigningTimeBiasInMs = ms;
  }

  public ContentInfo servicePkiOperation(CMSSignedData requestContent, AuditEvent event)
      throws MessageDecodingException, CaException {
    ScepUtil.requireNonNull("requestContent", requestContent);
    PrivateKey recipientKey = (raEmulator != null) ? raEmulator.getRaKey() : caEmulator.getCaKey();
    Certificate recipientCert =
        (raEmulator != null) ? raEmulator.getRaCert() : caEmulator.getCaCert();
    X509Certificate recipientX509Obj;
    try {
      recipientX509Obj = ScepUtil.toX509Cert(recipientCert);
    } catch (CertificateException ex) {
      throw new MessageDecodingException("could not parse recipientCert "
          + recipientCert.getTBSCertificate().getSubject());
    }

    EnvelopedDataDecryptorInstance decInstance =
        new EnvelopedDataDecryptorInstance(recipientX509Obj, recipientKey);
    EnvelopedDataDecryptor recipient = new EnvelopedDataDecryptor(decInstance);

    DecodedPkiMessage req = DecodedPkiMessage.decode(requestContent, recipient, null);

    PkiMessage rep = servicePkiOperation0(req, event);
    event.putEventData(ScepAuditConstants.NAME_pkiStatus, rep.getPkiStatus());
    if (rep.getPkiStatus() == PkiStatus.FAILURE) {
      event.setLevel(AuditLevel.ERROR);
    }

    if (rep.getFailInfo() != null) {
      event.putEventData(ScepAuditConstants.NAME_failInfo, rep.getFailInfo());
    }

    String signatureAlgorithm = ScepUtil.getSignatureAlgorithm(getSigningKey(),
        ScepHashAlgo.forNameOrOid(req.getDigestAlgorithm().getId()));

    try {
      X509Certificate jceSignerCert = ScepUtil.toX509Cert(getSigningCert());
      X509Certificate[] certs = control.isSendSignerCert()
          ? new X509Certificate[]{jceSignerCert} : null;

      return rep.encode(getSigningKey(), signatureAlgorithm, jceSignerCert, certs,
          req.getSignatureCert(), req.getContentEncryptionAlgorithm());
    } catch (Exception ex) {
      throw new CaException(ex);
    }
  } // method servicePkiOperation

  public ContentInfo encode(NextCaMessage nextCaMsg) throws CaException {
    ScepUtil.requireNonNull("nextCAMsg", nextCaMsg);
    try {
      X509Certificate jceSignerCert = ScepUtil.toX509Cert(getSigningCert());
      X509Certificate[] certs = control.isSendSignerCert()
          ? new X509Certificate[]{jceSignerCert} : null;
      return nextCaMsg.encode(getSigningKey(), jceSignerCert, certs);
    } catch (Exception ex) {
      throw new CaException(ex);
    }
  }

  private PkiMessage servicePkiOperation0(DecodedPkiMessage req, AuditEvent event)
      throws MessageDecodingException, CaException {
    TransactionId tid = req.getTransactionId();
    PkiMessage rep = new PkiMessage(tid, MessageType.CertRep, Nonce.randomNonce());
    rep.setPkiStatus(PkiStatus.SUCCESS);
    rep.setRecipientNonce(req.getSenderNonce());

    if (req.getFailureMessage() != null) {
      return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badRequest);
    }

    Boolean bo = req.isSignatureValid();
    if (bo != null && !bo.booleanValue()) {
      return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badMessageCheck);
    }

    bo = req.isDecryptionSuccessful();
    if (bo != null && !bo.booleanValue()) {
      return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badRequest);
    }

    Date signingTime = req.getSigningTime();
    if (maxSigningTimeBiasInMs > 0) {
      boolean isTimeBad = false;
      if (signingTime == null) {
        isTimeBad = true;
      } else {
        long now = System.currentTimeMillis();
        long diff = now - signingTime.getTime();
        if (diff < 0) {
          diff = -1 * diff;
        }
        isTimeBad = diff > maxSigningTimeBiasInMs;
      }

      if (isTimeBad) {
        return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badTime);
      }
    }

    // check the digest algorithm
    String oid = req.getDigestAlgorithm().getId();
    ScepHashAlgo hashAlgo = ScepHashAlgo.forNameOrOid(oid);
    if (hashAlgo == null) {
      LOG.warn("tid={}: unknown digest algorithm {}", tid, oid);
      return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badAlg);
    } // end if

    boolean supported = false;
    if (hashAlgo == ScepHashAlgo.SHA1) {
      if (caCaps.containsCapability(CaCapability.SHA1)) {
        supported = true;
      }
    } else if (hashAlgo == ScepHashAlgo.SHA256) {
      if (caCaps.containsCapability(CaCapability.SHA256)) {
        supported = true;
      }
    } else if (hashAlgo == ScepHashAlgo.SHA512) {
      if (caCaps.containsCapability(CaCapability.SHA512)) {
        supported = true;
      }
    } else if (hashAlgo == ScepHashAlgo.MD5) {
      if (control.isUseInsecureAlg()) {
        supported = true;
      }
    }

    if (!supported) {
      LOG.warn("tid={}: unsupported digest algorithm {}", tid, oid);
      return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badAlg);
    } // end if

    // check the content encryption algorithm
    ASN1ObjectIdentifier encOid = req.getContentEncryptionAlgorithm();
    if (CMSAlgorithm.DES_EDE3_CBC.equals(encOid)) {
      if (!caCaps.containsCapability(CaCapability.DES3)) {
        LOG.warn("tid={}: encryption with DES3 algorithm is not permitted", tid, encOid);
        return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badAlg);
      }
    } else if (AES_ENC_ALGS.contains(encOid)) {
      if (!caCaps.containsCapability(CaCapability.AES)) {
        LOG.warn("tid={}: encryption with AES algorithm {} is not permitted", tid, encOid);
        return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badAlg);
      }
    } else if (CMSAlgorithm.DES_CBC.equals(encOid)) {
      if (!control.isUseInsecureAlg()) {
        LOG.warn("tid={}: encryption with DES algorithm {} is not permitted", tid, encOid);
        return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badAlg);
      }
    } else {
      LOG.warn("tid={}: encryption with algorithm {} is not permitted", tid, encOid);
      return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badAlg);
    }

    if (rep.getPkiStatus() == PkiStatus.FAILURE) {
      return rep;
    }

    MessageType messageType = req.getMessageType();

    switch (messageType) {
      case PKCSReq:
        boolean selfSigned = req.getSignatureCert().getIssuerX500Principal()
            .equals(req.getSignatureCert().getIssuerX500Principal());

        CertificationRequest csr = CertificationRequest.getInstance(req.getMessageData());

        if (selfSigned) {
          X500Name name = X500Name.getInstance(
              req.getSignatureCert().getSubjectX500Principal().getEncoded());
          if (!name.equals(csr.getCertificationRequestInfo().getSubject())) {
            LOG.warn("tid={}: self-signed cert.subject != CSR.subject", tid);
            return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badRequest);
          }
        }

        String challengePwd = getChallengePassword(csr.getCertificationRequestInfo());
        if (challengePwd == null || !control.getSecret().equals(challengePwd)) {
          LOG.warn("challengePassword is not trusted");
          return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badRequest);
        }

        Certificate cert;
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

        break;
      case CertPoll:
        IssuerAndSubject is = IssuerAndSubject.getInstance(req.getMessageData());
        cert = caEmulator.pollCert(is.getIssuer(), is.getSubject());
        if (cert != null) {
          rep.setMessageData(createSignedData(cert));
        } else {
          buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badCertId);
        }

        break;
      case GetCert:
        IssuerAndSerialNumber isn = IssuerAndSerialNumber.getInstance(req.getMessageData());
        cert = caEmulator.getCert(isn.getName(),
                isn.getSerialNumber().getValue());
        if (cert != null) {
          rep.setMessageData(createSignedData(cert));
        } else {
          buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badCertId);
        }

        break;
      case RenewalReq:
        if (!caCaps.containsCapability(CaCapability.Renewal)) {
          buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badRequest);
        } else {
          csr = CertificationRequest.getInstance(req.getMessageData());
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
        }
        break;
      case UpdateReq:
        if (!caCaps.containsCapability(CaCapability.Update)) {
          buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badRequest);
        } else {
          csr = CertificationRequest.getInstance(req.getMessageData());
          try {
            cert = caEmulator.generateCert(csr);
          } catch (Exception ex) {
            throw new CaException("system failure: " + ex.getMessage(), ex);
          }
          if (cert != null) {
            rep.setMessageData(createSignedData(cert));
          } else {
            buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badCertId);
          }
        }
        break;
      case GetCRL:
        isn = IssuerAndSerialNumber.getInstance(req.getMessageData());
        CertificateList crl;
        try {
          crl = caEmulator.getCrl(isn.getName(), isn.getSerialNumber().getValue());
        } catch (Exception ex) {
          throw new CaException("system failure: " + ex.getMessage(), ex);
        }
        if (crl != null) {
          rep.setMessageData(createSignedData(crl));
        } else {
          buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badCertId);
        }
        break;
      default:
        buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badRequest);
    } // end switch

    return rep;
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
  }

  private ContentInfo createSignedData(Certificate cert) throws CaException {
    CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();

    CMSSignedData cmsSigneddata;
    try {
      cmsSignedDataGen.addCertificate(new X509CertificateHolder(cert));
      if (control.isSendCaCert()) {
        cmsSignedDataGen.addCertificate(new X509CertificateHolder(caEmulator.getCaCert()));
      }

      cmsSigneddata = cmsSignedDataGen.generate(new CMSAbsentContent());
    } catch (CMSException ex) {
      throw new CaException(ex);
    }

    return cmsSigneddata.toASN1Structure();
  }

  public PrivateKey getSigningKey() {
    return (raEmulator != null) ? raEmulator.getRaKey() : caEmulator.getCaKey();
  }

  public Certificate getSigningCert() {
    return (raEmulator != null) ? raEmulator.getRaCert() : caEmulator.getCaCert();
  }

  public CaCaps getCaCaps() {
    return caCaps;
  }

  public CaEmulator getCaEmulator() {
    return caEmulator;
  }

  public RaEmulator getRaEmulator() {
    return raEmulator;
  }

  public NextCaAndRa getNextCaAndRa() {
    return nextCaAndRa;
  }

  private static String getChallengePassword(CertificationRequestInfo csr) {
    ASN1Set attrs = csr.getAttributes();
    for (int i = 0; i < attrs.size(); i++) {
      Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
      if (PKCSObjectIdentifiers.pkcs_9_at_challengePassword.equals(attr.getAttrType())) {
        ASN1String str = (ASN1String) attr.getAttributeValues()[0];
        return str.getString();
      }
    }
    return null;
  }

  private static PkiMessage buildPkiMessage(PkiMessage message, PkiStatus status,
      FailInfo failInfo) {
    message.setPkiStatus(PkiStatus.FAILURE);
    message.setFailInfo(FailInfo.badRequest);
    return message;
  }

}
