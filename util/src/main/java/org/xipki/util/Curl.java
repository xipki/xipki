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

package org.xipki.util;

import java.util.Map;

/**
 * TODO.
 * @author Lijun Liao
 */

public interface Curl {

  public static class CurlResult {

    private String contentType;

    private byte[] content;

    private byte[] errorContent;

    public String getContentType() {
      return contentType;
    }

    public void setContentType(String contentType) {
      this.contentType = contentType;
    }

    public byte[] getContent() {
      return content;
    }

    public void setContent(byte[] content) {
      this.content = content;
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

  CurlResult curlPost(String url, boolean verbose, Map<String, String> headers, String userPassword,
      byte[] content) throws Exception;

}
