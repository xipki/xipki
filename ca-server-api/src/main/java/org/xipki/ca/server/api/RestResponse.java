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

package org.xipki.ca.server.api;

import java.util.Map;

import java.util.HashMap;

/**
 * TODO.
 * @author Lijun Liao
 * @since 3.0.1
 */

public class RestResponse {

  private int statusCode;

  private String contentType;

  private Map<String, String> headers = new HashMap<>();

  private byte[] body;

  public RestResponse(int statusCode, String contentType, Map<String, String> headers,
      byte[] body) {
    this.statusCode = statusCode;
    this.contentType = contentType;
    this.headers = headers;
    this.body = body;
  }

  public int statusCode() {
    return statusCode;
  }

  public void setStatusCode(int statusCode) {
    this.statusCode = statusCode;
  }

  public String contentType() {
    return contentType;
  }

  public void setContentType(String contentType) {
    this.contentType = contentType;
  }

  public Map<String, String> headers() {
    return headers;
  }

  public void setHeaders(Map<String, String> headers) {
    this.headers = headers;
  }

  public byte[] body() {
    return body;
  }

  public void setBody(byte[] body) {
    this.body = body;
  }

}
