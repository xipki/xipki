/*
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ocsp.client.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.ocsp.client.api.RequestOptions;

/**
 * @author Lijun Liao
 */

public class DefaultHttpOCSPRequestor extends AbstractOCSPRequestor
{
    // result in maximal 254 Base-64 encoded octets
    private static final int MAX_LEN_GET = 190;

    private static final String CT_REQUEST  = "application/ocsp-request";
    private static final String CT_RESPONSE = "application/ocsp-response";

    public DefaultHttpOCSPRequestor()
    {
    }

    @Override
    protected byte[] send(byte[] request, URL responderURL, RequestOptions requestOptions)
    throws IOException
    {
        int size = request.length;
        HttpURLConnection httpUrlConnection;
        if(size <= MAX_LEN_GET && requestOptions.isUseHttpGetForRequest())
        {
            String b64Request = Base64.toBase64String(request);

            StringBuilder urlBuilder = new StringBuilder();
            String baseUrl = responderURL.toString();
            urlBuilder.append(baseUrl);
            if(baseUrl.endsWith("/") == false)
            {
                urlBuilder.append('/');
            }
            urlBuilder.append(b64Request);
            URL newURL = new URL(urlBuilder.toString());

            httpUrlConnection = (HttpURLConnection) newURL.openConnection();
            httpUrlConnection.setRequestMethod("GET");
        }
        else
        {
            httpUrlConnection = (HttpURLConnection) responderURL.openConnection();
            httpUrlConnection.setDoOutput(true);
            httpUrlConnection.setUseCaches(false);

            httpUrlConnection.setRequestMethod("POST");
            httpUrlConnection.setRequestProperty("Content-Type", CT_REQUEST);
            httpUrlConnection.setRequestProperty("Content-Length", java.lang.Integer.toString(size));
            OutputStream outputstream = httpUrlConnection.getOutputStream();
            outputstream.write(request);
            outputstream.flush();
        }

        InputStream inputstream = httpUrlConnection.getInputStream();
        try
        {
            if (httpUrlConnection.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                throw new IOException("Bad Response: "
                        + httpUrlConnection.getResponseCode() + "  "
                        + httpUrlConnection.getResponseMessage());
            }
            String responseContentType = httpUrlConnection.getContentType();
            boolean isValidContentType = false;
            if (responseContentType != null)
            {
                if (responseContentType.equalsIgnoreCase(CT_RESPONSE))
                {
                    isValidContentType = true;
                }
            }
            if (isValidContentType == false)
            {
                throw new IOException("Bad Response: Mime type " + responseContentType + " not supported!");
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
