// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.crmf.DhSigStatic;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.xipki.security.DHSigStaticKeyCertPair;
import org.xipki.security.OIDs;
import org.xipki.security.SecurityFactory;
import org.xipki.security.exception.ErrorCode;
import org.xipki.security.exception.OperationException;
import org.xipki.security.util.EcCurveEnum;
import org.xipki.security.util.SecretKeyWithAlias;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.audit.AuditEvent;
import org.xipki.util.extra.audit.AuditLevel;
import org.xipki.util.extra.audit.AuditStatus;
import org.xipki.util.extra.audit.Audits;
import org.xipki.util.extra.audit.PciAuditEvent;
import org.xipki.util.extra.misc.LogUtil;

/**
 * Gateway Utilities.
 * @author Lijun Liao (xipki)
 */
public class GatewayUtil {

  public static void logAuditEvent(Logger log, AuditEvent event) {
    if (event == null) {
      return;
    }

    if (event.status() == AuditStatus.FAILED) {
      if (log.isWarnEnabled()) {
        log.warn(event.toTextMessage());
      }
    } else {
      if (log.isInfoEnabled()) {
        log.info(event.toTextMessage());
      }
    }
  }

  public static void logAuditEvent(Logger log, PciAuditEvent event) {
    if (event == null) {
      return;
    }

    if (event.level() == AuditLevel.WARN) {
      if (log.isWarnEnabled()) {
        log.warn(event.toTextMessage());
      }
    } else {
      if (log.isInfoEnabled()) {
        log.info(event.toTextMessage());
      }
    }
  }

  public static boolean verifyCsr(
      CertificationRequest csr, SecurityFactory securityFactory,
      PopControl popControl) {
    Args.notNull(popControl, "popControl");

    DHSigStaticKeyCertPair kaKeyAndCert = null;
    SecretKeyWithAlias kemMasterKey = null;

    AlgorithmIdentifier algId =
        Args.notNull(csr, "csr").getSignatureAlgorithm();
    ASN1ObjectIdentifier algOid = algId.getAlgorithm();

    if (OIDs.Xipki.id_alg_dhPop_x25519.equals(algOid)
        || OIDs.Xipki.id_alg_dhPop_x448.equals(algOid)) {
      DhSigStatic dhSigStatic = DhSigStatic.getInstance(
          csr.getSignature().getBytes());

      IssuerAndSerialNumber isn = dhSigStatic.getIssuerAndSerial();

      ASN1ObjectIdentifier keyOid = csr.getCertificationRequestInfo()
          .getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm();
      EcCurveEnum curve = EcCurveEnum.ofOid(keyOid);
      assert curve != null;
      kaKeyAndCert = popControl.getDhKeyCertPair(isn.getName(),
          isn.getSerialNumber().getValue(), curve.mainAlias());

      if (kaKeyAndCert == null) {
        return false;
      }
    } else if (OIDs.Xipki.id_alg_KEM_HMAC_SHA256.equals(algOid)) {
      ASN1Sequence seq = ASN1Sequence.getInstance(
          csr.getSignature().getBytes());

      String id = ((ASN1UTF8String) seq.getObjectAt(0)).getString();
      kemMasterKey = popControl.kemMasterKey(id);
      if (kemMasterKey == null) {
        return false;
      }
    }

    return securityFactory.verifyPop(csr,
        popControl.popAlgoValidator(), kaKeyAndCert,
        (kemMasterKey == null) ? null : kemMasterKey.secretKey());
  } // method verifyCsr

  public static void auditLogPciEvent(
      Logger log, String type, boolean successful, String eventType) {
    PciAuditEvent event = PciAuditEvent.newPciAuditEvent("SYSTEM",
        eventType, type,
        successful ? AuditStatus.SUCCESSFUL : AuditStatus.FAILED,
        successful ? AuditLevel.INFO : AuditLevel.ERROR);
    Audits.getAuditService().logEvent(event);
    logAuditEvent(log, event);
  }

  public static void closeAudits(Logger log) {
    if (Audits.getAuditService() != null) {
      try {
        Audits.getAuditService().close();
      } catch (Exception ex) {
        LogUtil.error(log, ex);
      }
    }
  }

  public static CertificationRequest parseCsrInRequest(byte[] csrBytes)
      throws OperationException {
    try {
      return CertificationRequest.getInstance(X509Util.toDerEncoded(
          Args.notNull(csrBytes, "csrBytes")));
    } catch (Exception ex) {
      throw new OperationException(ErrorCode.BAD_REQUEST,
          "invalid CSR: " + ex.getMessage());
    }
  }

  public static CertificationRequest parseCsrInRequest(ASN1Encodable p10Asn1)
      throws OperationException {
    try {
      return CertificationRequest.getInstance(p10Asn1);
    } catch (Exception ex) {
      throw new OperationException(ErrorCode.BAD_REQUEST,
          "invalid CSR: " + ex.getMessage());
    }
  }

}
