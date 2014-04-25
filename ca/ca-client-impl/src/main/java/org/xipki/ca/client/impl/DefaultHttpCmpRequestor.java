/*
 * Copyright (c) 2014 xipki.org
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

package org.xipki.ca.client.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.X509Certificate;

import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.ParamChecker;

class DefaultHttpCmpRequestor extends X509CmpRequestor
{
    private static final String CMP_REQUEST_MIMETYPE = "application/pkixcmp";
    private static final String CMP_RESPONSE_MIMETYPE = "application/pkixcmp";

    private final URL serverUrl;

    DefaultHttpCmpRequestor(ConcurrentContentSigner requestor,
            X509Certificate responderCert,
            X509Certificate caCert,
            String serverUrl,
            SecurityFactory securityFactory)
    {
        super(requestor, responderCert, caCert, securityFactory);
        ParamChecker.assertNotNull("serverUrl", serverUrl);

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
        InputStream inputstream = httpUrlConnection.getInputStream();
        try
        {
            if (httpUrlConnection.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                throw new IOException("Bad Response: "
                        + httpUrlConnection.getResponseCode() + "  "
                        + httpUrlConnection.getResponseMessage());
            }
            String responseContentType=httpUrlConnection.getContentType();
            boolean isValidContentType=false;
            if (responseContentType!=null)
            {
               if (responseContentType.equalsIgnoreCase(CMP_RESPONSE_MIMETYPE))
               {
                   isValidContentType=true;
               }
            }
            if (isValidContentType==false)
            {
                throw new IOException("Bad Response: Mime type "
                        + responseContentType
                        + " not supported!");
            }

            byte[] buf = new byte[4096];
            ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream();
            do
            {
                int j = inputstream.read(buf);
                if (j == -1)
                {
                    break;
                }
                bytearrayoutputstream.write(buf, 0, j);
            } while (true);

            return bytearrayoutputstream.toByteArray();
        }finally
        {
            inputstream.close();
        }
    }

}
