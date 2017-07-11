/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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

package org.xipki.pki.ca.server.mgmt.api;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.Base64;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.pki.ca.api.NameId;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CmpRequestorEntry {

    private static final Logger LOG = LoggerFactory.getLogger(CmpRequestorEntry.class);

    private final NameId ident;

    private final String base64Cert;

    private X509Certificate cert;

    public CmpRequestorEntry(final NameId ident, final String base64Cert) {
        this.ident = ParamUtil.requireNonNull("ident", ident);
        if (RequestorInfo.NAME_BY_USER.equalsIgnoreCase(ident.name())
                || RequestorInfo.NAME_BY_CA.equalsIgnoreCase(ident.name())) {
            throw new IllegalArgumentException("Requestor name could not be "
                    + RequestorInfo.NAME_BY_USER);
        }

        this.base64Cert = ParamUtil.requireNonBlank("base64Cert", base64Cert);
        try {
            this.cert = X509Util.parseBase64EncodedCert(base64Cert);
        } catch (Throwable th) {
            LogUtil.error(LOG, th,
                    "could not parse the certificate for requestor '" + ident + "'");
        }
    }

    public NameId ident() {
        return ident;
    }

    public String base64Cert() {
        return base64Cert;
    }

    public X509Certificate cert() {
        return cert;
    }

    @Override
    public String toString() {
        return toString(false);
    }

    public String toString(final boolean verbose) {
        StringBuilder sb = new StringBuilder(500);
        sb.append("id: ").append(ident.id()).append('\n');
        sb.append("name: ").append(ident.name()).append('\n');
        sb.append("faulty: ").append(cert == null).append('\n');

        if (cert != null) {
            sb.append("cert: ").append("\n");
            sb.append("\tissuer: ").append(
                    X509Util.getRfc4519Name(cert.getIssuerX500Principal())).append("\n");
            sb.append("\tserialNumber: ").append(LogUtil.formatCsn(cert.getSerialNumber()))
                    .append("\n");
            sb.append("\tsubject: ").append(
                    X509Util.getRfc4519Name(cert.getSubjectX500Principal())).append('\n');

            if (verbose) {
                sb.append("\tencoded: ");
                try {
                    sb.append(Base64.encodeToString(cert.getEncoded()));
                } catch (CertificateEncodingException ex) {
                    sb.append("ERROR");
                }
            }
        } else {
            sb.append("cert: null");
        }

        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof CmpRequestorEntry)) {
            return false;
        }

        CmpRequestorEntry objB = (CmpRequestorEntry) obj;
        if (!ident.equals(objB.ident)) {
            return false;
        }

        if (!base64Cert.equals(objB.base64Cert)) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        return ident.hashCode();
    }

}
