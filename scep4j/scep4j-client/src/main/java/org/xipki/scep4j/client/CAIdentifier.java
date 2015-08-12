/*
 * Copyright (c) 2015 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
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
        if (protocol.equalsIgnoreCase("http") == false && protocol.equalsIgnoreCase("https") == false)
        {
            throw new IllegalArgumentException("URL protocol should be HTTP or HTTPS, but not '" + protocol + "'");
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
