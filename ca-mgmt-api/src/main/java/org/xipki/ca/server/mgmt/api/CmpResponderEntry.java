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

package org.xipki.ca.server.mgmt.api;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.xipki.common.util.Base64;
import org.xipki.common.util.CompareUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.SignerConf;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CmpResponderEntry {

    private final String name;

    private final String type;

    private String conf;

    private boolean certFaulty;

    private boolean confFaulty;

    private final String base64Cert;

    private X509Certificate certificate;

    public CmpResponderEntry(String name, String type, String conf, String base64Cert) {
        this.name = ParamUtil.requireNonBlank("name", name).toUpperCase();
        this.type = ParamUtil.requireNonBlank("type", type);
        this.conf = conf;
        this.base64Cert = base64Cert;

        if (base64Cert == null) {
            return;
        }

        try {
            this.certificate = X509Util.parseBase64EncodedCert(base64Cert);
        } catch (Throwable th) {
            this.certFaulty = true;
        }
    }

    public String name() {
        return name;
    }

    public String type() {
        return type;
    }

    public void setConf(String conf) {
        this.conf = conf;
    }

    public String conf() {
        return conf;
    }

    public X509Certificate certificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        if (base64Cert != null) {
            throw new IllegalStateException("certificate is already specified by base64Cert");
        }
        this.certificate = certificate;
    }

    public String base64Cert() {
        return base64Cert;
    }

    public boolean isFaulty() {
        return confFaulty || certFaulty;
    }

    public void setConfFaulty(boolean confFaulty) {
        this.confFaulty = confFaulty;
    }

    @Override
    public String toString() {
        return toString(false);
    }

    public String toString(boolean verbose) {
        return toString(verbose, true);
    }

    public String toString(boolean verbose, boolean ignoreSensitiveInfo) {
        StringBuilder sb = new StringBuilder(1000);
        sb.append("name: ").append(name).append('\n');
        sb.append("faulty: ").append(isFaulty()).append('\n');
        sb.append("type: ").append(type).append('\n');
        sb.append("conf: ");
        if (conf == null) {
            sb.append("null");
        } else {
            sb.append(SignerConf.toString(conf, verbose, ignoreSensitiveInfo));
        }
        sb.append('\n');
        sb.append("certificate: ").append("\n");
        if (certificate != null || base64Cert != null) {
            if (certificate != null) {
                sb.append("\tissuer: ").append(X509Util.getRfc4519Name(
                        certificate.getIssuerX500Principal())).append('\n');
                sb.append("\tserialNumber: ")
                        .append(LogUtil.formatCsn(certificate.getSerialNumber())).append('\n');
                sb.append("\tsubject: ").append(X509Util.getRfc4519Name(
                        certificate.getSubjectX500Principal())).append('\n');
            }
            if (verbose) {
                sb.append("\tencoded: ");
                try {
                    sb.append(Base64.encodeToString(certificate.getEncoded()));
                } catch (CertificateEncodingException ex) {
                    sb.append("ERROR");
                }
            }
        } else {
            sb.append("null");
        }
        return sb.toString();
    } // method toString

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof CmpResponderEntry)) {
            return false;
        }

        CmpResponderEntry objB = (CmpResponderEntry) obj;
        if (!name.equals(objB.name)) {
            return false;
        }

        if (!type.equals(objB.type)) {
            return false;
        }

        if (!CompareUtil.equalsObject(conf, objB.conf)) {
            return false;
        }

        if (!CompareUtil.equalsObject(base64Cert, objB.base64Cert)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }

}
