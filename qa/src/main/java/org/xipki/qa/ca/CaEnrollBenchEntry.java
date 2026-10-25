// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AttributeOIDs;
import org.xipki.codec.asn1.oid.OIDs;
import org.xipki.pkix.asn1.x500.RDN;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.codec.util.Args;
import org.xipki.pkix.util.X509Util;

import java.util.List;

/**
 * CA Enroll Bench entry.
 *
 * @author Lijun Liao (xipki)
 */
public class CaEnrollBenchEntry {

  /**
   * Random Dn enumeration.
   */
  public enum RandomDn {

    GIVENNAME,
    SURNAME,
    STREET,
    POSTALCODE,
    O,
    OU,
    CN;

    public static RandomDn getInstance(String text) {
      Args.notNull(text, "text");
      for (RandomDn value : values()) {
        if (value.name().equalsIgnoreCase(text)) {
          return value;
        }
      }
      return null;
    }

  } // class RandomDN

  private static class IncreasableSubject {

    private final X500Name subjectTemplate;

    private final Asn1Oid subjectRdnForIncrement;

    private IncreasableSubject(String subjectTemplate, RandomDn randomDn) {
      Args.notNull(randomDn, "randomDn");

      this.subjectTemplate = new X500Name(Args.notBlank(subjectTemplate, "subjectTemplate"));

      switch (randomDn) {
        case GIVENNAME:
          this.subjectRdnForIncrement = AttributeOIDs.givenName;
          break;
        case SURNAME:
          this.subjectRdnForIncrement = AttributeOIDs.surname;
          break;
        case STREET:
          this.subjectRdnForIncrement = AttributeOIDs.street;
          break;
        case POSTALCODE:
          this.subjectRdnForIncrement = AttributeOIDs.postalCode;
          break;
        case O:
          this.subjectRdnForIncrement = AttributeOIDs.organization;
          break;
        case OU:
          this.subjectRdnForIncrement = AttributeOIDs.organizationalUnit;
          break;
        case CN:
          this.subjectRdnForIncrement = AttributeOIDs.commonName;
          break;
        default:
          throw new IllegalStateException("should not reach here, unknown randomDn " + randomDn);
      }

      if (this.subjectTemplate.getRDNs(this.subjectRdnForIncrement).isEmpty()) {
        throw new IllegalArgumentException("subjectTemplate does not contain DN field " +
            OIDs.oidToDisplayName(this.subjectRdnForIncrement));
      }
    } // constructor

    private X500Name getX500Name(long index) {
      List<RDN> baseRdns = subjectTemplate.getRDNs();

      final int n = baseRdns.size();
      RDN[] newRdns = new RDN[n];

      boolean incremented = false;
      for (int i = 0; i < n; i++) {
        RDN rdn = baseRdns.get(i);
        if (!incremented) {
          if (rdn.getFirst().getType().equals(subjectRdnForIncrement)) {
            String text = X509Util.rdnValueToString(rdn.getFirst().getValue());
            rdn = new RDN(subjectRdnForIncrement, new Asn1Utf8String(text + index));
            incremented = true;
          }
        }

        newRdns[i] = rdn;
      }
      return new X500Name(newRdns);
    } // method getX500Name

  } // class IncreasableSubject

  private final String certprofile;

  private final CaEnrollBenchKeyEntry keyEntry;

  private final IncreasableSubject subject;

  public CaEnrollBenchEntry(String certprofile, CaEnrollBenchKeyEntry keyEntry,
                            String subjectTemplate, RandomDn randomDn) {
    this.certprofile = Args.notBlank(certprofile, "certprofile");
    this.keyEntry = keyEntry;
    this.subject = new IncreasableSubject(subjectTemplate, randomDn);
  }

  public SubjectPublicKeyInfo getSubjectPublicKeyInfo() throws Exception {
    return keyEntry == null ? null : keyEntry.getSubjectPublicKeyInfo();
  }

  public X500Name getX500Name(long index) {
    return subject.getX500Name(index);
  }

  public String getCertprofile() {
    return certprofile;
  }

}
