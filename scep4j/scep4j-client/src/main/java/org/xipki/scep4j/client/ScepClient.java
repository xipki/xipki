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
        } catch (IOException e)
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
            if (request != null)
            {
                if (requestContentType != null)
                {
                    conn.setRequestProperty("Content-Type", requestContentType);
                }
                conn.setRequestProperty("Content-Length",
                        java.lang.Integer.toString(request.length));
                OutputStream outputstream = conn.getOutputStream();
                outputstream.write(request);
                outputstream.flush();
            }

            return parseResponse(conn);
        } catch (IOException e)
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
            if (contentEncoding != null && !contentEncoding.isEmpty())
            {
                resp.setContentEncoding(contentEncoding);
            }
            return resp;
        } catch (IOException e)
        {
            throw new ScepClientException(e);
        }
    }

}
