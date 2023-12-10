// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.xipki.util.Args;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * CMP request to enroll certificates.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class EnrollCertRequest {

  public enum EnrollType {

    CERT_REQ,
    INIT_REQ,
    KEY_UPDATE,
    CROSS_CERT_REQ

  } // class EnrollType

  public static class Entry extends IdentifiedObject {

    private final String certprofile;

    private final CertRequest certReq;

    private final ProofOfPossession pop;

    public Entry(String id, String certprofile, CertRequest certReq, ProofOfPossession pop) {
      super(id);

      this.certprofile = Args.notBlank(certprofile, "certprofile");
      this.certReq = Args.notNull(certReq, "certReq");
      this.pop = Args.notNull(pop, "pop");
    }

    public Entry(String id, String certprofile, CertRequest certReq,
                 ProofOfPossession pop, boolean serverkeygen, boolean reenroll) {
      super(id);

      this.certprofile = reenroll ? certprofile : Args.notBlank(certprofile, "certprofile");
      this.certReq = Args.notNull(certReq, "certReq");
      if (!serverkeygen) {
        Args.notNull(pop, "pop");
      }
      this.pop = pop;
    }

    public String getCertprofile() {
      return certprofile;
    }

    public CertRequest getCertReq() {
      return certReq;
    }

    public ProofOfPossession getPop() {
      return pop;
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
    String id = Args.notNull(requestEntry, "requestEntry").getId();
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
  }

  public List<Entry> getRequestEntries() {
    return Collections.unmodifiableList(requestEntries);
  }

}
