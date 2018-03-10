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

package org.xipki.ca.client.shell.loadtest;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class LoadTestEntry {

  public enum RandomDn {

    GIVENNAME,
    SURNAME,
    STREET,
    POSTALCODE,
    O,
    OU,
    CN;

    public static RandomDn getInstance(String text) {
      ParamUtil.requireNonNull("text", text);
      for (RandomDn value : values()) {
        if (value.name().equalsIgnoreCase(text)) {
          return value;
        }
      }
      return null;
    }

  } // enum RandomDN

  private static class IncreasableSubject {

    private final X500Name subjectTemplate;

    private final ASN1ObjectIdentifier subjectRdnForIncrement;

    private IncreasableSubject(String subjectTemplate, RandomDn randomDn) {
      ParamUtil.requireNonBlank("subjectTemplate", subjectTemplate);
      ParamUtil.requireNonNull("randomDn", randomDn);

      this.subjectTemplate = new X500Name(subjectTemplate);

      switch (randomDn) {
        case GIVENNAME:
          this.subjectRdnForIncrement = ObjectIdentifiers.DN_GIVENNAME;
          break;
        case SURNAME:
          this.subjectRdnForIncrement = ObjectIdentifiers.DN_SURNAME;
          break;
        case STREET:
          this.subjectRdnForIncrement = ObjectIdentifiers.DN_STREET;
          break;
        case POSTALCODE:
          this.subjectRdnForIncrement = ObjectIdentifiers.DN_POSTAL_CODE;
          break;
        case O:
          this.subjectRdnForIncrement = ObjectIdentifiers.DN_O;
          break;
        case OU:
          this.subjectRdnForIncrement = ObjectIdentifiers.DN_OU;
          break;
        case CN:
          this.subjectRdnForIncrement = ObjectIdentifiers.DN_CN;
          break;
        default:
          throw new RuntimeException("should not reach here, unknown randomDn " + randomDn);
      }

      if (this.subjectRdnForIncrement != null
          && this.subjectTemplate.getRDNs(this.subjectRdnForIncrement).length == 0) {
        throw new IllegalArgumentException("subjectTemplate does not contain DN field "
            + ObjectIdentifiers.oidToDisplayName(this.subjectRdnForIncrement));
      }
    }

    private X500Name getX500Name(long index) {
      RDN[] baseRdns = subjectTemplate.getRDNs();

      final int n = baseRdns.length;
      RDN[] newRdns = new RDN[n];

      boolean incremented = false;
      for (int i = 0; i < n; i++) {
        RDN rdn = baseRdns[i];
        if (!incremented) {
          if (rdn.getFirst().getType().equals(subjectRdnForIncrement)) {
            String text = X509Util.rdnValueToString(rdn.getFirst().getValue());
            rdn = new RDN(subjectRdnForIncrement, new DERUTF8String(text + index));
            incremented = true;
          }
        }

        newRdns[i] = rdn;
      }
      return new X500Name(newRdns);
    }

  } // class IncreasableSubject

  private final String certprofile;

  private final KeyEntry keyEntry;

  private final IncreasableSubject subject;

  public LoadTestEntry(String certprofile, KeyEntry keyEntry, String subjectTemplate,
        RandomDn randomDn) {
    this.certprofile = ParamUtil.requireNonBlank("certprofile", certprofile);
    this.keyEntry = ParamUtil.requireNonNull("keyEntry", keyEntry);
    this.subject = new IncreasableSubject(subjectTemplate, randomDn);
  }

  public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
    return keyEntry.getSubjectPublicKeyInfo();
  }

  public X500Name getX500Name(long index) {
    return subject.getX500Name(index);
  }

  public String certprofile() {
    return certprofile;
  }

}
