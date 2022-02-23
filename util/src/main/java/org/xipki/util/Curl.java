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

package org.xipki.util;

import java.io.OutputStream;
import java.util.Map;

/**
 * This interface specifies similar operations like the Linux command curl.
 *
 * @author Lijun Liao
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

  CurlResult curlPost(String url, boolean verbose, Map<String, String> headers, String userPassword,
      byte[] content)
          throws Exception;

  CurlResult curlPost(String url, OutputStream respContentStream, boolean verbose,
                      Map<String, String> headers, String userPassword, byte[] content)
          throws Exception;

}
