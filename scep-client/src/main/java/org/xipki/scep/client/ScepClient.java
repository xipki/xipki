/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.scep.client;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

import org.xipki.scep.client.exception.ScepClientException;
import org.xipki.scep.util.ScepUtil;

/**
 * @author Lijun Liao
 */

public class ScepClient extends Client {

    public ScepClient(final CaIdentifier caId, final CaCertValidator caCertValidator)
            throws MalformedURLException {
        super(caId, caCertValidator);
    }

    @Override
    protected ScepHttpResponse httpGet(final String url) throws ScepClientException {
        ScepUtil.requireNonNull("url", url);
        try {
            HttpURLConnection httpConn = openHttpConn(new URL(url));
            httpConn.setRequestMethod("GET");
            return parseResponse(httpConn);
        } catch (IOException ex) {
            throw new ScepClientException(ex);
        }
    }

    @Override
    protected ScepHttpResponse httpPost(final String url, final String requestContentType,
            final byte[] request) throws ScepClientException {
        ScepUtil.requireNonNull("url", url);
        try {
            HttpURLConnection httpConn = openHttpConn(new URL(url));
            httpConn.setDoOutput(true);
            httpConn.setUseCaches(false);

            httpConn.setRequestMethod("POST");
            if (request != null) {
                if (requestContentType != null) {
                    httpConn.setRequestProperty("Content-Type", requestContentType);
                }
                httpConn.setRequestProperty("Content-Length", Integer.toString(request.length));
                OutputStream outputstream = httpConn.getOutputStream();
                outputstream.write(request);
                outputstream.flush();
            }

            return parseResponse(httpConn);
        } catch (IOException ex) {
            throw new ScepClientException(ex.getMessage(), ex);
        }
    }

    protected ScepHttpResponse parseResponse(final HttpURLConnection conn)
            throws ScepClientException {
        ScepUtil.requireNonNull("conn", conn);
        try {
            InputStream inputstream = conn.getInputStream();
            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
                inputstream.close();

                throw new ScepClientException("bad response: " + conn.getResponseCode() + "    "
                        + conn.getResponseMessage());
            }
            String contentType = conn.getContentType();
            int contentLength = conn.getContentLength();

            ScepHttpResponse resp = new ScepHttpResponse(contentType, contentLength, inputstream);
            String contentEncoding = conn.getContentEncoding();
            if (contentEncoding != null && !contentEncoding.isEmpty()) {
                resp.setContentEncoding(contentEncoding);
            }
            return resp;
        } catch (IOException ex) {
            throw new ScepClientException(ex);
        }
    }

    private static HttpURLConnection openHttpConn(final URL url) throws IOException {
        ScepUtil.requireNonNull("url", url);
        URLConnection conn = url.openConnection();
        if (conn instanceof HttpURLConnection) {
            return (HttpURLConnection) conn;
        }
        throw new IOException(url.toString() + " is not of protocol HTTP: " + url.getProtocol());
    }

}
