/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.client.shell.loadtest;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.commons.security.api.util.X509Util;

/**
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

        public static RandomDn getInstance(
                final String text) {
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

        private IncreasableSubject(
                final String subjectTemplate,
                final RandomDn randomDn) {
            ParamUtil.requireNonEmpty("subjectTemplate", subjectTemplate);
            ParamUtil.requireNonNull("randomDn", randomDn);

            this.subjectTemplate = X509Util.sortX509Name(new X500Name(subjectTemplate));

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
                throw new RuntimeException("should not reach here, unknown RandomDn "
                        + randomDn);
            }

            if (this.subjectRdnForIncrement != null
                    && this.subjectTemplate.getRDNs(this.subjectRdnForIncrement).length == 0) {
                throw new IllegalArgumentException("subjectTemplate does not contain DN field "
                        + ObjectIdentifiers.oidToDisplayName(this.subjectRdnForIncrement));
            }
        }

        private X500Name getX500Name(
                final long index) {
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

    public LoadTestEntry(
            final String certprofile,
            final KeyEntry keyEntry,
            final String subjectTemplate,
            final RandomDn randomDn) {
        this.certprofile = ParamUtil.requireNonBlank("certprofile", certprofile);
        this.keyEntry = ParamUtil.requireNonNull("keyEntry", keyEntry);
        this.subject = new IncreasableSubject(subjectTemplate, randomDn);
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo(
            final long index) {
        return keyEntry.getSubjectPublicKeyInfo(index);
    }

    public X500Name getX500Name(
            final long index) {
        return subject.getX500Name(index);
    }

    public String getCertprofile() {
        return certprofile;
    }

}
