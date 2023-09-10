// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client;

import org.xipki.util.Args;
import org.xipki.util.IoUtil;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * HTTP Response.
 *
 * @author Lijun Liao (xipki)
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

  public ScepHttpResponse(String contentType, byte[] contentBytes) {
    this(contentType, Args.notNull(contentBytes, "contentBytes").length, new ByteArrayInputStream(contentBytes));
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
      return IoUtil.readAllBytesAndClose(content);
    } catch (IOException ex) {
      throw new ScepClientException(ex);
    }
  }

}
