/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
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

package org.xipki.ca.server;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

/**
 * @author Lijun Liao
 */

public class PublicCAInfo
{
    private final X509Certificate caCertificate;
    private X509Certificate crlSignerCertificate;
    private final List<String> ocspUris;
    private final List<String> crlUris;
    private final List<String> caIssuerLocations;
    private final List<String> deltaCrlUris;

    public PublicCAInfo(X509Certificate caCertificate,
            List<String> ocspUris, List<String> crlUris,
            List<String> caIssuerLocations, List<String> deltaCrlUris)
    {
        this.caCertificate = caCertificate;
        this.ocspUris = ocspUris;
        this.crlUris = crlUris;
        this.caIssuerLocations = caIssuerLocations;
        this.deltaCrlUris = deltaCrlUris;
    }

    public X509Certificate getCACertificate()
    {
        return caCertificate;
    }

    public List<String> getOcspUris()
    {
        return ocspUris == null ? null : Collections.unmodifiableList(ocspUris);
    }

    public List<String> getCrlUris()
    {
        return crlUris == null ? null : Collections.unmodifiableList(crlUris);
    }

    public List<String> getCaIssuerLocations()
    {
        return caIssuerLocations == null ? null : Collections.unmodifiableList(caIssuerLocations);
    }

    public List<String> getDeltaCrlUris()
    {
        return deltaCrlUris == null ? null : Collections.unmodifiableList(deltaCrlUris);
    }

    public X509Certificate getCrlSignerCertificate()
    {
        return crlSignerCertificate;
    }

    public void setCrlSignerCertificate(X509Certificate crlSignerCert)
    {
        if(caCertificate.equals(crlSignerCert))
        {
            this.crlSignerCertificate = null;
        }
        else
        {
            this.crlSignerCertificate = crlSignerCert;
        }
    }
}
