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

package org.xipki.pki.ca.dbtool.report;

import org.xipki.pki.ca.dbtool.xmlio.InvalidDataObjectException;

/**
 * @author Lijun Liao
 */

public class ReportEntry
{
    private Integer id;
    private Long serialNumber;
    private Boolean revoked;
    private Integer revReason;
    private Long revTime;
    private Long revInvTime;
    private String base64Sha1;

    public Integer getId()
    {
        return id;
    }

    public void setId(Integer id)
    {
        this.id = id;
    }

    public Long getSerialNumber()
    {
        return serialNumber;
    }

    public void setSerialNumber(Long serialNumber)
    {
        this.serialNumber = serialNumber;
    }

    public Boolean getRevoked()
    {
        return revoked;
    }

    public void setRevoked(Boolean revoked)
    {
        this.revoked = revoked;
    }

    public Integer getRevReason()
    {
        return revReason;
    }

    public void setRevReason(Integer revReason)
    {
        this.revReason = revReason;
    }

    public Long getRevTime()
    {
        return revTime;
    }

    public void setRevTime(Long revTime)
    {
        this.revTime = revTime;
    }

    public Long getRevInvTime()
    {
        return revInvTime;
    }

    public void setRevInvTime(Long revInvTime)
    {
        this.revInvTime = revInvTime;
    }

    public String getBase64Sha1()
    {
        return base64Sha1;
    }

    public void setBase64Sha1(String base64Sha1)
    {
        this.base64Sha1 = base64Sha1;
    }

    public void validate()
    throws InvalidDataObjectException
    {
        assertNotNull("id", id);
        assertNotNull("serialNumber", serialNumber);
        assertNotNull("revoked", revoked);
        if(revoked)
        {
            assertNotNull("revReason", revReason);
            assertNotNull("revTime", revTime);
        }
        assertNotBlank("base64Sha1", base64Sha1);
    }

    private static void assertNotNull(
            final String name,
            final Object value)
    throws InvalidDataObjectException
    {
        if(value == null)
        {
            throw new InvalidDataObjectException(name + " could not be null");
        }
    }

    private static void assertNotBlank(
            final String name,
            final String value)
    throws InvalidDataObjectException
    {
        if(value == null || value.isEmpty())
        {
            throw new InvalidDataObjectException(name + " could not be blank");
        }
    }

    public String getEncoded()
    throws InvalidDataObjectException
    {
        validate();
        StringBuilder sb = new StringBuilder();
        sb.append(id).append(";");
        sb.append(serialNumber).append(";");
        sb.append(revoked ? "1" : "0").append(";");

        if(revReason != null)
        {
            sb.append(revReason);
        }
        sb.append(";");

        if(revTime != null)
        {
            sb.append(revTime);
        }
        sb.append(";");

        if(revInvTime != null)
        {
            sb.append(revInvTime);
        }
        sb.append(";");

        sb.append(base64Sha1);
        return sb.toString();
    }
}
