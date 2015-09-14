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

package org.xipki.scep4j.client;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

import org.xipki.scep4j.transaction.Operation;
import org.xipki.scep4j.transaction.TransactionException;
import org.xipki.scep4j.util.ScepUtil;

/**
 * @author Lijun Liao
 */

public class CAIdentifier
{
    private final String url;
    private final String profile;

    public CAIdentifier(
            final String serverUrl,
            final String profile)
    throws MalformedURLException
    {
        URL url = new URL(serverUrl);
        final String protocol = url.getProtocol();
        if (protocol.equalsIgnoreCase("http") == false
                && protocol.equalsIgnoreCase("https") == false)
        {
            throw new IllegalArgumentException(
                    "URL protocol should be HTTP or HTTPS, but not '" + protocol + "'");
        }

        if (url.getQuery() != null)
        {
            throw new IllegalArgumentException("URL should contain no query string");
        }

        this.url = serverUrl;
        this.profile = profile;
    }

    public String getUrl()
    {
        return url;
    }

    public String getProfile()
    {
        return profile;
    }

    public String buildGetUrl(
            final Operation operation)
    throws TransactionException
    {
        return buildGetUrl(operation, null);
    }

    @SuppressWarnings("deprecation")
    public String buildGetUrl(
            final Operation operation,
            final String message)
    {
        StringBuilder ub = new StringBuilder(url);
        ub.append('?').append("operation=").append(operation.getCode());
        if(ScepUtil.isBlank(message) == false)
        {
            String _urlMessage;
            try
            {
                _urlMessage = URLEncoder.encode(message, "UTF-8");
            } catch (UnsupportedEncodingException e)
            {
                _urlMessage = URLEncoder.encode(message);
            }
            ub.append("&message=").append(_urlMessage);
        }
        return ub.toString();
    }

    public String buildPostUrl(
            final Operation operation)
    {
        StringBuilder ub = new StringBuilder(url);
        ub.append('?').append("operation=").append(operation.getCode());
        return ub.toString();
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("URL: ").append(url);
        if(ScepUtil.isNotBlank(profile))
        {
            sb.append(", CA-Ident: ").append(profile);
        }
        return sb.toString();
    }

    @Override
    public boolean equals(
            final Object object)
    {
        if(object instanceof CAIdentifier)
        {
            CAIdentifier b = (CAIdentifier) object;
            return url == b.url && profile == b.profile;
        }
        return false;
    }

    @Override
    public int hashCode()
    {
        return toString().hashCode();
    }

}
