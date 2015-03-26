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

package org.xipki.ocsp.client.shell;

import org.xipki.ocsp.client.api.OCSPResponseException;

/**
 * @author Lijun Liao
 */

@SuppressWarnings("serial")
public class OCSPResponseUnsuccessfulException extends OCSPResponseException
{
    private int status;
    public OCSPResponseUnsuccessfulException(
            final int status)
    {
        super(getOCSPResponseStatus(status));
        this.status = status;
    }

    public int getStatus()
    {
        return status;
    }

    public String getStatusText()
    {
        return getOCSPResponseStatus(status);
    }

    private static String getOCSPResponseStatus(
            final int statusCode)
    {
        switch(statusCode)
        {
        case 1:
            return "malformedRequest";
        case 2:
            return "internalError";
        case 3:
            return "tryLater";
        case 5:
            return "sigRequired";
        case 6:
            return "unauthorized";
        default:
            return "undefined";
        }
    }

}
