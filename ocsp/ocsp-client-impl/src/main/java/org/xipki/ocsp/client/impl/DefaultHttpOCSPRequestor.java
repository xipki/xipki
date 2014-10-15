/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.client.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.security.common.IoCertUtil;

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
            String urlEncodedReq = URLEncoder.encode(b64Request, "UTF-8");
            StringBuilder urlBuilder = new StringBuilder();
            String baseUrl = responderURL.toString();
            urlBuilder.append(baseUrl);
            if(baseUrl.endsWith("/") == false)
            {
                urlBuilder.append('/');
            }
            urlBuilder.append(urlEncodedReq);

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
        if (httpUrlConnection.getResponseCode() != HttpURLConnection.HTTP_OK)
        {
            inputstream.close();
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
            inputstream.close();
            throw new IOException("Bad Response: Mime type " + responseContentType + " not supported!");
        }

        return IoCertUtil.read(inputstream);
    }

}
