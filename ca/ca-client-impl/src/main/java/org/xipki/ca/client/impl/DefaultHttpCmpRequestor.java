/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.client.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.X509Certificate;

import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class DefaultHttpCmpRequestor extends X509CmpRequestor
{
    private static final String CMP_REQUEST_MIMETYPE = "application/pkixcmp";
    private static final String CMP_RESPONSE_MIMETYPE = "application/pkixcmp";

    private final URL serverUrl;

    DefaultHttpCmpRequestor(X509Certificate requestorCert,
            X509Certificate responderCert,
            String serverUrl,
            SecurityFactory securityFactory)
    {
        super(requestorCert, responderCert, securityFactory);
        ParamChecker.assertNotEmpty("serverUrl", serverUrl);

        try
        {
            this.serverUrl = new URL(serverUrl);
        } catch (MalformedURLException e)
        {
            throw new IllegalArgumentException("Invalid url: " + serverUrl);
        }
    }

    DefaultHttpCmpRequestor(ConcurrentContentSigner requestor,
            X509Certificate responderCert,
            String serverUrl,
            SecurityFactory securityFactory,
            boolean signRequest)
    {
        super(requestor, responderCert, securityFactory, signRequest);
        ParamChecker.assertNotEmpty("serverUrl", serverUrl);

        try
        {
            this.serverUrl = new URL(serverUrl);
        } catch (MalformedURLException e)
        {
            throw new IllegalArgumentException("Invalid url: " + serverUrl);
        }
    }

    @Override
    public byte[] send(byte[] request)
    throws IOException
    {
        HttpURLConnection httpUrlConnection = (HttpURLConnection) serverUrl.openConnection();
        httpUrlConnection.setDoOutput(true);
        httpUrlConnection.setUseCaches(false);

        int size = request.length;

        httpUrlConnection.setRequestMethod("POST");
        httpUrlConnection.setRequestProperty("Content-Type", CMP_REQUEST_MIMETYPE);
        httpUrlConnection.setRequestProperty("Content-Length", java.lang.Integer.toString(size));
        OutputStream outputstream = httpUrlConnection.getOutputStream();
        outputstream.write(request);
        outputstream.flush();

        InputStream inputStream = httpUrlConnection.getInputStream();
        if (httpUrlConnection.getResponseCode() != HttpURLConnection.HTTP_OK)
        {
            inputStream.close();
            throw new IOException("Bad Response: "
                    + httpUrlConnection.getResponseCode() + "  "
                    + httpUrlConnection.getResponseMessage());
        }
        String responseContentType = httpUrlConnection.getContentType();
        boolean isValidContentType = false;
        if (responseContentType != null)
        {
            if (responseContentType.equalsIgnoreCase(CMP_RESPONSE_MIMETYPE))
            {
                isValidContentType = true;
            }
        }
        if (isValidContentType == false)
        {
            inputStream.close();
            throw new IOException("Bad Response: Mime type "
                    + responseContentType
                    + " not supported!");
        }

        return IoCertUtil.read(inputStream);
    }

}
