/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.scep.client.exception.ScepClientException;
import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public class ScepHttpResponse {

  private static final Logger LOG = LoggerFactory.getLogger(ScepHttpResponse.class);

  private final String contentType;

  private final int contentLength;

  private final InputStream content;

  private String contentEncoding;

  public ScepHttpResponse(String contentType, int contentLength, InputStream content) {
    this.contentType = ScepUtil.requireNonNull("contentType", contentType);
    this.content = ScepUtil.requireNonNull("content", content);
    this.contentLength = contentLength;
  }

  public ScepHttpResponse(String contentType, int contentLength, byte[] contentBytes) {
    this(contentType, contentLength,
        new ByteArrayInputStream(ScepUtil.requireNonNull("contentBytes", contentBytes)));
  }

  public String getContentType() {
    return contentType;
  }

  public int getContentLength() {
    return contentLength;
  }

  public String getContentEncoding() {
    return contentEncoding;
  }

  public void setContentEncoding(String contentEncoding) {
    this.contentEncoding = contentEncoding;
  }

  public InputStream getContent() {
    return content;
  }

  public byte[] getContentBytes() throws ScepClientException {
    if (content == null) {
      return null;
    }

    try {
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      int readed = 0;
      byte[] buffer = new byte[2048];
      while ((readed = content.read(buffer)) != -1) {
        bout.write(buffer, 0, readed);
      }

      return bout.toByteArray();
    } catch (IOException ex) {
      throw new ScepClientException(ex);
    } finally {
      if (content != null) {
        try {
          content.close();
        } catch (IOException ex) {
          LOG.error("could not close stream: {}", ex.getMessage());
        }
      }
    }
  }

}
