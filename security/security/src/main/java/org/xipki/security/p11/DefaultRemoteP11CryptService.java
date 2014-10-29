/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.ParamChecker;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11ModuleConf;

/**
 * @author Lijun Liao
 */

class DefaultRemoteP11CryptService extends RemoteP11CryptService
{
    private static final String CMP_REQUEST_MIMETYPE = "application/pkixcmp";
    private static final String CMP_RESPONSE_MIMETYPE = "application/pkixcmp";

    private URL _serverUrl;
    private final String serverUrl;

    DefaultRemoteP11CryptService(P11ModuleConf moduleConf)
    {
        super(moduleConf);

        ParamChecker.assertNotNull("moduleConf", moduleConf);

        CmpUtf8Pairs conf = new CmpUtf8Pairs(moduleConf.getNativeLibrary());
        serverUrl = conf.getValue("url");
        if(serverUrl == null || serverUrl.isEmpty())
        {
            throw new IllegalArgumentException("url is not specified");
        }

        try
        {
            _serverUrl = new URL(serverUrl);
        } catch (MalformedURLException e)
        {
            throw new IllegalArgumentException("Invalid url: " + serverUrl);
        }
    }

    @Override
    public byte[] send(byte[] request)
    throws IOException
    {
        HttpURLConnection httpUrlConnection = (HttpURLConnection) _serverUrl.openConnection();
        httpUrlConnection.setDoOutput(true);
        httpUrlConnection.setUseCaches(false);

        int size = request.length;

        httpUrlConnection.setRequestMethod("POST");
        httpUrlConnection.setRequestProperty("Content-Type", CMP_REQUEST_MIMETYPE);
        httpUrlConnection.setRequestProperty("Content-Length", java.lang.Integer.toString(size));
        OutputStream outputstream = httpUrlConnection.getOutputStream();
        outputstream.write(request);
        outputstream.flush();

        InputStream inputstream = null;
        try
        {
            inputstream = httpUrlConnection.getInputStream();
        }catch(IOException e)
        {
            InputStream errStream = httpUrlConnection.getErrorStream();
            if(errStream != null)
            {
                errStream.close();
            }
            throw e;
        }

        try
        {
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

    @Override
    public void refresh()
    throws SignerException
    {
    }

    public String getServerUrl()
    {
        return serverUrl;
    }

}
