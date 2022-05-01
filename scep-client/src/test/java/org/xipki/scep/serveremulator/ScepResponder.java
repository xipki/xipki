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

package org.xipki.scep.serveremulator;

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
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cms.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.scep.message.*;
import org.xipki.scep.message.EnvelopedDataDecryptor.EnvelopedDataDecryptorInstance;
import org.xipki.scep.serveremulator.AuditEvent.AuditLevel;
import org.xipki.scep.transaction.*;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

/**
 * SCEP responder.
 *
 * @author Lijun Liao
 */

public class ScepResponder {

  private static final Logger LOG = LoggerFactory.getLogger(ScepResponder.class);

  private static final long DFLT_MAX_SIGNINGTIME_BIAS = 5L * 60 * 1000; // 5 minutes

  private final CaCaps caCaps;

  private final CaEmulator caEmulator;

  private final RaEmulator raEmulator;

  private final NextCaAndRa nextCaAndRa;

  private final ScepControl control;

  private long maxSigningTimeBiasInMs = DFLT_MAX_SIGNINGTIME_BIAS;

  public ScepResponder(CaCaps caCaps, CaEmulator caEmulator, RaEmulator raEmulator,
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
   * Set the maximal allowed bias of signing time during the signature verification.
   *
   * @param ms signing time bias in milliseconds. non-positive value deactivate
   *        the check of signing time.
   */
  public void setMaxSigningTimeBias(long ms) {
    this.maxSigningTimeBiasInMs = ms;
  }

  public ContentInfo servicePkiOperation(CMSSignedData requestContent, AuditEvent event)
      throws MessageDecodingException, CaException, NoSuchAlgorithmException {
    Args.notNull(requestContent, "requestContent");
    PrivateKey recipientKey = (raEmulator != null) ? raEmulator.getRaKey() : caEmulator.getCaKey();
    X509Cert recipientCert =
        (raEmulator != null) ? raEmulator.getRaCert() : caEmulator.getCaCert();

    EnvelopedDataDecryptorInstance decInstance =
        new EnvelopedDataDecryptorInstance(recipientCert, recipientKey);
    EnvelopedDataDecryptor recipient = new EnvelopedDataDecryptor(decInstance);

    DecodedPkiMessage req = DecodedPkiMessage.decode(requestContent, recipient, null);

    PkiMessage rep = servicePkiOperation0(req);
    event.putEventData(AuditEvent.NAME_pkiStatus, rep.getPkiStatus());
    if (rep.getPkiStatus() == PkiStatus.FAILURE) {
      event.setLevel(AuditLevel.ERROR);
    }

    if (rep.getFailInfo() != null) {
      event.putEventData(AuditEvent.NAME_failInfo, rep.getFailInfo());
    }

    SignAlgo signatureAlgorithm = SignAlgo.getInstance(getSigningKey(),
        req.getDigestAlgorithm(), null);

    try {
      X509Cert jceSignerCert = getSigningCert();
      X509Cert[] certs = control.isSendSignerCert()
          ? new X509Cert[]{jceSignerCert} : null;

      return rep.encode(getSigningKey(), signatureAlgorithm, jceSignerCert, certs,
          req.getSignatureCert(), req.getContentEncryptionAlgorithm());
    } catch (Exception ex) {
      throw new CaException(ex);
    }
  } // method servicePkiOperation

  public ContentInfo encode(NextCaMessage nextCaMsg)
      throws CaException {
    Args.notNull(nextCaMsg, "nextCaMsg");
    try {
      X509Cert jceSignerCert = getSigningCert();
      X509Cert[] certs = control.isSendSignerCert()
          ? new X509Cert[]{jceSignerCert} : null;
      return nextCaMsg.encode(getSigningKey(), jceSignerCert, certs);
    } catch (Exception ex) {
      throw new CaException(ex);
    }
  }

  private PkiMessage servicePkiOperation0(DecodedPkiMessage req)
      throws CaException {
    TransactionId tid = req.getTransactionId();
    PkiMessage rep = new PkiMessage(tid, MessageType.CertRep, Nonce.randomNonce());
    rep.setPkiStatus(PkiStatus.SUCCESS);
    rep.setRecipientNonce(req.getSenderNonce());

    if (req.getFailureMessage() != null) {
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

    Date signingTime = req.getSigningTime();
    if (maxSigningTimeBiasInMs > 0) {
      boolean isTimeBad;
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
    HashAlgo hashAlgo = req.getDigestAlgorithm();

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
    ASN1ObjectIdentifier encOid = req.getContentEncryptionAlgorithm();
    if (CMSAlgorithm.DES_EDE3_CBC.equals(encOid)) {
      if (!caCaps.supportsDES3()) {
        LOG.warn("tid={}: encryption with DES3 algorithm {} is not permitted", tid, encOid);
        return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badAlg);
      }
    } else if (CMSAlgorithm.AES128_CBC.equals(encOid)) {
      if (!caCaps.supportsAES()) {
        LOG.warn("tid={}: encryption with AES algorithm {} is not permitted", tid, encOid);
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
        boolean selfSigned = req.getSignatureCert().isSelfSigned();

        CertificationRequest csr = CertificationRequest.getInstance(req.getMessageData());

        if (selfSigned) {
          X500Name name = req.getSignatureCert().getSubject();
          if (!name.equals(csr.getCertificationRequestInfo().getSubject())) {
            LOG.warn("tid={}: self-signed cert.subject != CSR.subject", tid);
            return buildPkiMessage(rep, PkiStatus.FAILURE, FailInfo.badRequest);
          }
        }

        String challengePwd = getChallengePassword(csr.getCertificationRequestInfo());
        if (!control.getSecret().equals(challengePwd)) {
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
        if (!caCaps.supportsRenewal()) {
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

  private ContentInfo createSignedData(CertificateList crl)
      throws CaException {
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

  private ContentInfo createSignedData(X509Cert cert)
      throws CaException {
    CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();

    CMSSignedData cmsSigneddata;
    try {
      cmsSignedDataGen.addCertificate(cert.toBcCert());
      if (control.isSendCaCert()) {
        cmsSignedDataGen.addCertificate(caEmulator.getCaCert().toBcCert());
      }

      cmsSigneddata = cmsSignedDataGen.generate(new CMSAbsentContent());
    } catch (CMSException ex) {
      throw new CaException(ex);
    }

    return cmsSigneddata.toASN1Structure();
  } // method createSignedData

  public PrivateKey getSigningKey() {
    return (raEmulator != null) ? raEmulator.getRaKey() : caEmulator.getCaKey();
  }

  public X509Cert getSigningCert() {
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
  } // method getChallengePassword

  private static PkiMessage buildPkiMessage(PkiMessage message, PkiStatus status,
      FailInfo failInfo) {
    message.setPkiStatus(status);
    message.setFailInfo(failInfo);
    return message;
  }

}
