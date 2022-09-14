/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.ca.gateway;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.crmf.DhSigStatic;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.slf4j.Logger;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditStatus;
import org.xipki.security.*;

import static org.xipki.util.Args.notNull;

/**
 * Gateway Utilities.
 * @author Lijun Liao
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

  public static boolean verifyCsr(CertificationRequest csr, SecurityFactory securityFactory, PopControl popControl) {
    notNull(csr, "csr");
    notNull(popControl, "popControl");

    ASN1ObjectIdentifier algOid = csr.getSignatureAlgorithm().getAlgorithm();

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

}
