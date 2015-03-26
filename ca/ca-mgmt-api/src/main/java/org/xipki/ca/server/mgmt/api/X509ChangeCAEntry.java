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
import java.util.List;

/**
 * @author Lijun Liao
 */

public class X509ChangeCAEntry
extends ChangeCAEntry
implements Serializable
{
    private static final long serialVersionUID = 1L;

    private List<String> crlUris;
    private List<String> deltaCrlUris;
    private List<String> ocspUris;
    private List<String> issuerLocations;
    private X509Certificate cert;
    private String crlSignerName;
    private String cmpControlName;
    private Integer numCrls;
    private String extraControl;

    public X509ChangeCAEntry(
            final String name)
    throws CAMgmtException
    {
        super(name);
    }

    public List<String> getCrlUris()
    {
        return crlUris;
    }

    public void setCrlUris(
            final List<String> crlUris)
    {
        this.crlUris = crlUris;
    }

    public List<String> getDeltaCrlUris()
    {
        return deltaCrlUris;
    }

    public void setDeltaCrlUris(
            final List<String> deltaCrlUris)
    {
        this.deltaCrlUris = deltaCrlUris;
    }

    public List<String> getOcspUris()
    {
        return ocspUris;
    }

    public void setOcspUris(
            final List<String> ocspUris)
    {
        this.ocspUris = ocspUris;
    }

    public List<String> getIssuerLocations()
    {
        return issuerLocations;
    }

    public void setIssuerLocations(
            final List<String> issuerLocations)
    {
        this.issuerLocations = issuerLocations;
    }

    public X509Certificate getCert()
    {
        return cert;
    }

    public void setCert(
            final X509Certificate cert)
    {
        this.cert = cert;
    }

    public String getCrlSignerName()
    {
        return crlSignerName;
    }

    public void setCrlSignerName(
            final String crlSignerName)
    {
        this.crlSignerName = crlSignerName;
    }

    public String getCmpControlName()
    {
        return cmpControlName;
    }

    public void setCmpControlName(
            final String cmpControlName)
    {
        this.cmpControlName = cmpControlName;
    }

    public Integer getNumCrls()
    {
        return numCrls;
    }

    public void setNumCrls(
            final Integer numCrls)
    {
        this.numCrls = numCrls;
    }

    public String getExtraControl()
    {
        return extraControl;
    }

    public void setExtraControl(
            final String extraControl)
    {
        this.extraControl = extraControl;
    }

}
