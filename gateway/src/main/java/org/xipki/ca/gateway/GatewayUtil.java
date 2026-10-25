// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway;

import org.slf4j.Logger;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.pkix.asn1.cms.IssuerAndSerialNumber;
import org.xipki.pkix.asn1.crmf.DhSigStatic;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.oid.XipkiOIDs;
import org.xipki.pkix.asn1.pkcs10.CertificationRequest;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.pkix.SecurityFactory;
import org.xipki.pkix.exception.ErrorCode;
import org.xipki.pkix.exception.OperationException;
import org.xipki.pkix.cert.DHSigStaticKeyCertPair;
import org.xipki.pkix.sign.KemHmacSignature;
import org.xipki.crypto.core.EcCurveEnum;
import org.xipki.crypto.core.SecretKeyWithAlias;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.audit.AuditEvent;
import org.xipki.util.audit.AuditLevel;
import org.xipki.util.audit.AuditStatus;
import org.xipki.util.audit.Audits;
import org.xipki.util.audit.PciAuditEvent;
import org.xipki.pkix.util.misc.LogUtil;

/**
 * Gateway Util.
 *
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

  public static boolean verifyCsr(CertificationRequest csr, SecurityFactory securityFactory,
                                  PopControl popControl) {
    Args.notNull(popControl, "popControl");

    DHSigStaticKeyCertPair kaKeyAndCert = null;
    SecretKeyWithAlias kemMasterKey = null;

    AlgorithmIdentifier algId = Args.notNull(csr, "csr").getSignatureAlgorithm();
    Asn1Oid algOid = algId.getAlgorithm();

    if (XipkiOIDs.id_alg_dhPop_x25519.equals(algOid)
        || XipkiOIDs.id_alg_dhPop_x448.equals(algOid)) {
      DhSigStatic dhSigStatic;
      try {
        dhSigStatic = DhSigStatic.fromEncoded(csr.signature());
      } catch (CodecException e) {
        return false;
      }

      IssuerAndSerialNumber isn = dhSigStatic.getIssuerAndSerial();

      Asn1Oid keyOid = csr.getSubjectPKInfo().getAlgorithm().getAlgorithm();
      EcCurveEnum curve = EcCurveEnum.ofOid(keyOid);
      assert curve != null;
      kaKeyAndCert = popControl.getDhKeyCertPair(isn.getName(),
          isn.serialNumber(), curve.mainAlias());

      if (kaKeyAndCert == null) {
        return false;
      }
    } else if (XipkiOIDs.id_alg_KEM_HMAC_SHA256.equals(algOid)) {
      KemHmacSignature sig;
      try {
        sig = KemHmacSignature.decode(csr.signature());
      } catch (CodecException e) {
        return false;
      }

      kemMasterKey = popControl.kemMasterKey(sig.id());
      if (kemMasterKey == null) {
        return false;
      }
    }

    return securityFactory.verifyPop(csr, popControl.popAlgoValidator(), kaKeyAndCert,
        (kemMasterKey == null) ? null : kemMasterKey.secretKey());
  } // method verifyCsr

  public static void auditLogPciEvent(
      Logger log, String type, boolean successful, String eventType) {
    PciAuditEvent event = PciAuditEvent.newPciAuditEvent("SYSTEM", eventType, type,
        successful ? AuditStatus.SUCCESSFUL : AuditStatus.FAILED,
        successful ? AuditLevel.INFO        : AuditLevel.ERROR);
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
      return CertificationRequest.fromEncoded(X509Util.toDerEncoded(
          Args.notNull(csrBytes, "csrBytes")));
    } catch (Exception ex) {
      throw new OperationException(ErrorCode.BAD_REQUEST, "invalid CSR: " + ex.getMessage());
    }
  }

  public static CertificationRequest parseCsrInRequest(Asn1Sequence p10Asn1)
      throws OperationException {
    try {
      return CertificationRequest.fromAsn1(p10Asn1);
    } catch (Exception ex) {
      throw new OperationException(ErrorCode.BAD_REQUEST, "invalid CSR: " + ex.getMessage());
    }
  }

}
