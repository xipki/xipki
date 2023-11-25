// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.crmf.DhSigStatic;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.slf4j.Logger;
import org.xipki.audit.*;
import org.xipki.pki.ErrorCode;
import org.xipki.pki.OperationException;
import org.xipki.security.*;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.LogUtil;

/**
 * Gateway Utilities.
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class GatewayUtil {

  public static void logAuditEvent(Logger log, AuditEvent event) {
    if (event == null) {
      return;
    }

    if (event.getStatus() == AuditStatus.FAILED) {
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

    if (event.getLevel() == AuditLevel.WARN) {
      if (log.isWarnEnabled()) {
        log.warn(event.toTextMessage());
      }
    } else {
      if (log.isInfoEnabled()) {
        log.info(event.toTextMessage());
      }
    }
  }

  public static boolean verifyCsr(CertificationRequest csr, SecurityFactory securityFactory, PopControl popControl) {
    Args.notNull(popControl, "popControl");

    ASN1ObjectIdentifier algOid = Args.notNull(csr, "csr").getSignatureAlgorithm().getAlgorithm();

    DHSigStaticKeyCertPair kaKeyAndCert = null;
    if (ObjectIdentifiers.Xipki.id_alg_dhPop_x25519.equals(algOid)
        || ObjectIdentifiers.Xipki.id_alg_dhPop_x448.equals(algOid)) {
      DhSigStatic dhSigStatic = DhSigStatic.getInstance(csr.getSignature().getBytes());
      IssuerAndSerialNumber isn = dhSigStatic.getIssuerAndSerial();

      ASN1ObjectIdentifier keyOid = csr.getCertificationRequestInfo().getSubjectPublicKeyInfo()
          .getAlgorithm().getAlgorithm();
      kaKeyAndCert = popControl.getDhKeyCertPair(isn.getName(), isn.getSerialNumber().getValue(),
          EdECConstants.getName(keyOid));

      if (kaKeyAndCert == null) {
        return false;
      }
    }

    AlgorithmValidator popValidator = popControl.getPopAlgoValidator();

    return securityFactory.verifyPop(csr, popValidator, kaKeyAndCert);
  } // method verifyCsr

  public static void auditLogPciEvent(Logger log, String type, boolean successful, String eventType) {
    PciAuditEvent event = PciAuditEvent.newPciAuditEvent(type, eventType, "CORE",
        successful ? AuditStatus.SUCCESSFUL : AuditStatus.FAILED, successful ? AuditLevel.INFO : AuditLevel.ERROR);
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

  public static CertificationRequest parseCsrInRequest(byte[] csrBytes) throws OperationException {
    try {
      return CertificationRequest.getInstance(X509Util.toDerEncoded(
          Args.notNull(csrBytes, "csrBytes")));
    } catch (Exception ex) {
      throw new OperationException(ErrorCode.BAD_REQUEST, "invalid CSR: " + ex.getMessage());
    }
  }

  public static CertificationRequest parseCsrInRequest(ASN1Encodable p10Asn1) throws OperationException {
    try {
      return CertificationRequest.getInstance(p10Asn1);
    } catch (Exception ex) {
      throw new OperationException(ErrorCode.BAD_REQUEST, "invalid CSR: " + ex.getMessage());
    }
  }

}
