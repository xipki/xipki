/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import org.xipki.util.Args;
import org.xipki.util.IoUtil;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * HTTP Response.
 *
 * @author Lijun Liao
 */

public class ScepHttpResponse {

  private final String contentType;

  private final int contentLength;

  private final InputStream content;

  private String contentEncoding;

  public ScepHttpResponse(String contentType, int contentLength, InputStream content) {
    this.contentType = Args.notNull(contentType, "contentType");
    this.content = Args.notNull(content, "content");
    this.contentLength = contentLength;
  }

  public ScepHttpResponse(String contentType, int contentLength, byte[] contentBytes) {
    this(contentType, contentLength,
        new ByteArrayInputStream(Args.notNull(contentBytes, "contentBytes")));
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

  public byte[] getContentBytes()
      throws ScepClientException {
    if (content == null) {
      return null;
    }

    try {
      return IoUtil.read(content);
    } catch (IOException ex) {
      throw new ScepClientException(ex);
    }
  }

}
