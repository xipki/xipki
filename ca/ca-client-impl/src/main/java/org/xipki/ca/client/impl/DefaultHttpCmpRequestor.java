/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
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
