/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License
 * (version 3 or later at your option)
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

package org.xipki.security.common;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Date;

import org.bouncycastle.asn1.cmp.PKIHeader;

/**
 * @author Lijun Liao
 */

public class BCCompatilbilityUtil
{
    private static Method pkiHeader_getMessageTime;

    static
    {
        try
        {
            pkiHeader_getMessageTime = PKIHeader.class.getMethod("getMessageTime");
        }catch(NoSuchMethodException e)
        {
        }
    }

    public static Date getMessageTime(PKIHeader pkiHeader)
    {
        if(pkiHeader_getMessageTime == null)
        {
            throw new RuntimeException("unsupported BouncyCastle version");
        }

        try
        {
            Object o = pkiHeader_getMessageTime.invoke(pkiHeader);
            if(o == null)
            {
                return null;
            }

            Method m = o.getClass().getMethod("getDate");
            return (Date) m.invoke(o);
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException |
                NoSuchMethodException | SecurityException e)
        {
            throw new RuntimeException(e.getClass().getName() + ": " + e.getMessage(), e);
        }
    }

}
