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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import org.xipki.scep4j.client.exception.ScepClientException;

/**
 * @author Lijun Liao
 */

public class ScepClient extends Client
{

    public ScepClient(
            final CAIdentifier cAId,
            final CACertValidator cACertValidator)
    throws MalformedURLException
    {
        super(cAId, cACertValidator);
    }

    @Override
    protected ScepHttpResponse httpGET(
            final String url)
    throws ScepClientException
    {
        try
        {
            URL _url = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) _url.openConnection();
            conn.setRequestMethod("GET");
            return parseResponse(conn);
        }catch(IOException e)
        {
            throw new ScepClientException(e);
        }
    }

    @Override
    protected ScepHttpResponse httpPOST(
            final String url,
            final String requestContentType,
            final byte[] request)
    throws ScepClientException
    {
        try
        {
            URL _url = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) _url.openConnection();
            conn.setDoOutput(true);
            conn.setUseCaches(false);

            conn.setRequestMethod("POST");
            if(request != null)
            {
                if(requestContentType != null)
                {
                    conn.setRequestProperty("Content-Type", requestContentType);
                }
                conn.setRequestProperty("Content-Length", java.lang.Integer.toString(request.length));
                OutputStream outputstream = conn.getOutputStream();
                outputstream.write(request);
                outputstream.flush();
            }

            return parseResponse(conn);
        }catch(IOException e)
        {
            throw new ScepClientException(e.getMessage(), e);
        }
    }

    protected ScepHttpResponse parseResponse(
            final HttpURLConnection conn)
    throws ScepClientException
    {
        try
        {
            InputStream inputstream = conn.getInputStream();
            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                inputstream.close();

                throw new ScepClientException("bad response: "
                        + conn.getResponseCode() + "  "
                        + conn.getResponseMessage());
            }
            String contentType = conn.getContentType();
            int contentLength = conn.getContentLength();

            ScepHttpResponse resp = new ScepHttpResponse(contentType, contentLength, inputstream);
            String contentEncoding = conn.getContentEncoding();
            if(contentEncoding != null && contentEncoding.isEmpty() == false)
            {
                resp.setContentEncoding(contentEncoding);
            }
            return resp;
        }catch(IOException e)
        {
            throw new ScepClientException(e);
        }
    }

}
