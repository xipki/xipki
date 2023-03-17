// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.io.OutputStream;
import java.util.Map;

/**
 * This interface specifies similar operations like the Linux command curl.
 *
 * @author Lijun Liao (xipki)
 */

public interface Curl {

  class CurlResult {

    private String contentType;

    /**
     * Length of the content, independent whether it is written to the {@link #content}
     * or contentStream.
     */
    private int contentLength;

    /**
     * Content may be null, if it is written to contentStream.
     */
    private byte[] content;

    private byte[] errorContent;

    public String getContentType() {
      return contentType;
    }

    public void setContentType(String contentType) {
      this.contentType = contentType;
    }

    public int getContentLength() {
      return contentLength;
    }

    public void setContentLength(int contentLength) {
      this.contentLength = contentLength;
    }

    public byte[] getContent() {
      return content;
    }

    public void setContent(byte[] content) {
      this.content = content;
      this.contentLength = content == null ? 0 : content.length;
    }

    public byte[] getErrorContent() {
      return errorContent;
    }

    public void setErrorContent(byte[] errorContent) {
      this.errorContent = errorContent;
    }

  }

  CurlResult curlGet(String url, boolean verbose, Map<String, String> headers, String userPassword)
      throws Exception;

  CurlResult curlGet(String url, OutputStream respContentStream, boolean verbose,
                     Map<String, String> headers, String userPassword)
      throws Exception;

  CurlResult curlPost(String url, boolean verbose, Map<String, String> headers, String userPassword, byte[] content)
      throws Exception;

  CurlResult curlPost(String url, OutputStream respContentStream, boolean verbose,
                      Map<String, String> headers, String userPassword, byte[] content)
      throws Exception;

}
