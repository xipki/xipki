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

package org.xipki.pki.ca.server.mgmt.api;

import java.io.Serializable;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.InvalidConfException;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.util.SecurityUtil;
import org.xipki.commons.security.api.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509CrlSignerEntry implements Serializable {

    private static final Logger LOG = LoggerFactory.getLogger(X509CrlSignerEntry.class);

    private static final long serialVersionUID = 1L;

    private final String name;

    private final String signerType;

    private final String signerConf;

    private final String base64Cert;

    private X509Certificate cert;

    private boolean certFaulty;

    private boolean confFaulty;

    private String crlControl;

    public X509CrlSignerEntry(
            final String name,
            final String signerType,
            final String signerConf,
            final String base64Cert,
            final String crlControl)
    throws InvalidConfException {
        ParamUtil.assertNotBlank("name", name);
        ParamUtil.assertNotBlank("type", signerType);
        ParamUtil.assertNotNull("crlControl", crlControl);

        if ("CA".equalsIgnoreCase(name)) {
            this.base64Cert = null;
        } else {
            this.base64Cert = base64Cert;
        }

        this.name = name;
        this.signerType = signerType;
        this.signerConf = signerConf;
        this.crlControl = crlControl;

        if (this.base64Cert != null) {
            try {
                this.cert = X509Util.parseBase64EncodedCert(base64Cert);
            } catch (Throwable th) {
                LOG.debug("could not parse the certificate of CRL signer '" + name + "'");
                certFaulty = true;
            }
        }
    }

    public String getName() {
        return name;
    }

    public void setConfFaulty(
            final boolean faulty) {
        this.confFaulty = faulty;
    }

    public boolean isFaulty() {
        return certFaulty || confFaulty;
    }

    public String getType() {
        return signerType;
    }

    public String getConf() {
        return signerConf;
    }

    public String getBase64Cert() {
        return base64Cert;
    }

    public X509Certificate getCertificate() {
        return cert;
    }

    public void setCertificate(
            final X509Certificate certificate) {
        if (base64Cert != null) {
            throw new IllegalStateException("certificate is already by specified by base64Cert");
        }
        this.cert = certificate;
    }

    public String getCrlControl() {
        return crlControl;
    }

    @Override
    public String toString() {
        return toString(false);
    }

    public String toString(
            final boolean verbose) {
        return toString(verbose, true);
    }

    public String toString(
            final boolean verbose,
            final boolean ignoreSensitiveInfo) {
        StringBuilder sb = new StringBuilder(1000);
        sb.append("name: ").append(name).append('\n');
        sb.append("faulty: ").append(isFaulty()).append('\n');
        sb.append("signerType: ").append(signerType).append('\n');
        sb.append("signerConf: ");
        if (signerConf == null) {
            sb.append("null");
        } else {
            sb.append(SecurityUtil.signerConfToString(signerConf, verbose, ignoreSensitiveInfo));
        }
        sb.append('\n');
        sb.append("crlControl: ").append(crlControl).append("\n");
        if (cert != null) {
            sb.append("cert: ").append("\n");
            sb.append("\tissuer: ").append(
                    X509Util.getRfc4519Name(cert.getIssuerX500Principal())).append('\n');
            sb.append("\tserialNumber: ").append(cert.getSerialNumber()).append('\n');
            sb.append("\tsubject: ").append(
                    X509Util.getRfc4519Name(cert.getSubjectX500Principal())).append('\n');

            if (verbose) {
                sb.append("\tencoded: ");
                try {
                    sb.append(Base64.toBase64String(cert.getEncoded()));
                } catch (CertificateEncodingException ex) {
                    sb.append("ERROR");
                }
            }
        } else {
            sb.append("cert: null\n");
        }

        return sb.toString();
    } // method toString

}
