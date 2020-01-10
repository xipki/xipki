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

package org.xipki.cmpclient;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.xipki.util.Args;

/**
 * CMP request to enroll certificates.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class EnrollCertRequest {

  public static enum EnrollType {

    CERT_REQ,
    INIT_REQ,
    KEY_UPDATE,
    CROSS_CERT_REQ;

  } // class EnrollType

  public static class Entry extends IdentifiedObject {

    private final String certprofile;

    private final CertRequest certReq;

    private final ProofOfPossession popo;

    private final boolean caGenerateKeypair;

    public Entry(String id, String certprofile, CertRequest certReq,
        ProofOfPossession popo) {
      super(id);

      this.certprofile = Args.notBlank(certprofile, "certprofile");
      this.certReq = Args.notNull(certReq, "certReq");
      this.caGenerateKeypair = false;
      this.popo = Args.notNull(popo, "popo");
    }

    public Entry(String id, String certprofile, CertRequest certReq,
        ProofOfPossession popo, boolean caGenerateKeypair, boolean kup) {
      super(id);

      this.certprofile = kup ? certprofile : Args.notBlank(certprofile, "certprofile");
      this.certReq = Args.notNull(certReq, "certReq");
      this.caGenerateKeypair = caGenerateKeypair;
      if (!caGenerateKeypair) {
        Args.notNull(popo, "popo");
      }
      this.popo = popo;
    }

    public String getCertprofile() {
      return certprofile;
    }

    public CertRequest getCertReq() {
      return certReq;
    }

    public ProofOfPossession getPopo() {
      return popo;
    }

    public boolean isCaGenerateKeypair() {
      return caGenerateKeypair;
    }

  } // class Entry

  private final EnrollType type;

  private final List<Entry> requestEntries = new LinkedList<>();

  public EnrollCertRequest(EnrollType type) {
    this.type = Args.notNull(type, "type");
  }

  public EnrollType getType() {
    return type;
  }

  public boolean addRequestEntry(Entry requestEntry) {
    Args.notNull(requestEntry, "requestEntry");
    String id = requestEntry.getId();
    ASN1Integer certReqId = requestEntry.getCertReq().getCertReqId();
    for (Entry re : requestEntries) {
      if (re.getId().equals(id)) {
        return false;
      }

      if (re.getCertReq().getCertReqId().equals(certReqId)) {
        return false;
      }
    }

    requestEntries.add(requestEntry);
    return true;
  } // method addRequestEntry

  public List<Entry> getRequestEntries() {
    return Collections.unmodifiableList(requestEntries);
  }

}
