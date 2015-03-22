/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.ca.server.mgmt.api;

import java.io.Serializable;
import java.security.cert.X509Certificate;

import org.xipki.common.util.SecurityUtil;

/**
 * @author Lijun Liao
 */

public class CmpResponderEntry implements Serializable
{
    private static final long serialVersionUID = 1L;
    public static final String name = "default";
    private String type;
    private String conf;
    private boolean certFaulty;
    private boolean confFaulty;
    private String base64Cert;
    private X509Certificate cert;

    public CmpResponderEntry()
    {
    }

    public String getType()
    {
        return type;
    }

    public void setType(String type)
    {
        this.type = type;
    }

    public String getConf()
    {
        return conf;
    }

    public void setConf(String conf)
    {
        this.conf = conf;
    }

    public X509Certificate getCertificate()
    {
        return cert;
    }

    public void setCertificate(X509Certificate cert)
    {
        if(base64Cert != null)
        {
            throw new IllegalStateException("certificate is already specified by base64Cert");
        }
        this.cert = cert;
    }

    public String getBase64Cert()
    {
        return base64Cert;
    }

    public void setBase64Cert(String base64Cert)
    {
        this.certFaulty = false;
        this.base64Cert = base64Cert;
        try
        {
            this.cert = SecurityUtil.parseBase64EncodedCert(base64Cert);
        }catch(Throwable t)
        {
            this.certFaulty = true;
        }
    }

    public boolean isFaulty()
    {
        return confFaulty || certFaulty;
    }

    public void setConfFaulty(boolean confFaulty)
    {
        this.confFaulty = confFaulty;
    }

    @Override
    public String toString()
    {
        return toString(false);
    }

    public String toString(boolean verbose)
    {
        return toString(verbose, true);
    }

    public String toString(boolean verbose, boolean ignoreSensitiveInfo)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("name: ").append(name).append('\n');
        sb.append("faulty: ").append(isFaulty()).append('\n');
        sb.append("type: ").append(type).append('\n');
        sb.append("conf: ");
        if(conf == null)
        {
            sb.append("null");
        } else
        {
            sb.append(SecurityUtil.signerConfToString(conf, verbose, ignoreSensitiveInfo));
        }
        sb.append('\n');
        sb.append("cert: ").append("\n");
        if(cert != null)
        {
            sb.append("\tissuer: ").append(
                    SecurityUtil.getRFC4519Name(cert.getIssuerX500Principal())).append('\n');
            sb.append("\tserialNumber: ").append(cert.getSerialNumber()).append('\n');
            sb.append("\tsubject: ").append(
                    SecurityUtil.getRFC4519Name(cert.getSubjectX500Principal())).append('\n');
            if(verbose)
            {
                sb.append("\tencoded: ").append(base64Cert);
            }
        }
        else
        {
            sb.append("null");
        }
        return sb.toString();
    }

}
