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

package org.xipki.ca.server;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.ca.mgmt.api.MgmtEntry;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignerEntryWrapper {

  private MgmtEntry.Signer dbEntry;

  private ConcurrentContentSigner signer;

  private X500Name subjectAsX500Name;

  private GeneralName subjectAsGeneralName;

  public SignerEntryWrapper() {
  }

  public void setDbEntry(MgmtEntry.Signer dbEntry) {
    this.dbEntry = Args.notNull(dbEntry, "dbEntry");
    signer = null;
    if (dbEntry.getCertificate() != null) {
      subjectAsX500Name = X500Name.getInstance(
          dbEntry.getCertificate().getSubjectX500Principal().getEncoded());
      subjectAsGeneralName = new GeneralName(subjectAsX500Name);
    }
  }

  public ConcurrentContentSigner getSigner() {
    return signer;
  }

  public void initSigner(SecurityFactory securityFactory) throws ObjectCreationException {
    Args.notNull(securityFactory, "securityFactory");
    if (signer != null) {
      return;
    }

    if (dbEntry == null) {
      throw new ObjectCreationException("dbEntry is null");
    }

    X509Certificate responderCert = dbEntry.getCertificate();
    dbEntry.setConfFaulty(true);
    signer = securityFactory.createSigner(dbEntry.getType(), new SignerConf(dbEntry.getConf()),
        responderCert);
    if (signer.getCertificate() == null) {
      throw new ObjectCreationException("signer without certificate is not allowed");
    }
    dbEntry.setConfFaulty(false);

    if (dbEntry.getBase64Cert() == null) {
      dbEntry.setCertificate(signer.getCertificate());
      subjectAsX500Name = X500Name.getInstance(signer.getBcCertificate().getSubject());
      subjectAsGeneralName = new GeneralName(subjectAsX500Name);
    }
  } // method initSigner

  public MgmtEntry.Signer getDbEntry() {
    return dbEntry;
  }

  public boolean isHealthy() {
    return (signer == null) ? false : signer.isHealthy();
  }

  public GeneralName getSubjectAsGeneralName() {
    return subjectAsGeneralName;
  }

  public X500Name getSubjectAsX500Name() {
    return subjectAsX500Name;
  }

}
