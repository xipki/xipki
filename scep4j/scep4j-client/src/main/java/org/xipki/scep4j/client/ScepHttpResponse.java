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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.xipki.scep4j.client.exception.ScepClientException;

/**
 * @author Lijun Liao
 */

public class ScepHttpResponse
{
    private final String contentType;
    private final int contentLength;
    private final InputStream content;
    private String contentEncoding;

    public ScepHttpResponse(
            final String contentType,
            final int contentLength,
            final InputStream content)
    {
        this.contentType = contentType;
        this.content = content;
        this.contentLength = contentLength;
    }

    public ScepHttpResponse(
            final String contentType,
            final int contentLength,
            final byte[] contentBytes)
    {
        this.contentType = contentType;
        this.content = new ByteArrayInputStream(contentBytes);
        this.contentLength = contentLength;
    }

    public String getContentType()
    {
        return contentType;
    }

    public int getContentLength()
    {
        return contentLength;
    }

    public String getEncoding()
    {
        return contentEncoding;
    }

    public void setContentEncoding(
            final String contentEncoding)
    {
        this.contentEncoding = contentEncoding;
    }

    public InputStream getContent()
    {
        return content;
    }

    public byte[] getContentBytes()
    throws ScepClientException
    {
        if(content == null)
        {
            return null;
        }

        try
        {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            int readed = 0;
            byte[] buffer = new byte[2048];
            while ((readed = content.read(buffer)) != -1)
            {
                bout.write(buffer, 0, readed);
            }

            return bout.toByteArray();
        } catch(IOException e)
        {
            throw new ScepClientException(e);
        } finally
        {
            if (content != null)
            {
                try
                {
                    content.close();
                } catch (IOException e)
                {
                }
            }
        }
    }

}
