// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.http;

/**
 * HTTP response.
 *
 * @author Lijun Liao (xipki)
 */

public class HttpRespContent {

  private final String contentType;

  private final byte[] content;

  private final boolean base64;

  private final int statusCode;

  private HttpRespContent(int statusCode, String contentType, boolean base64, byte[] content) {
    this.contentType = contentType;
    this.content = content;
    this.base64 = base64;
    this.statusCode = statusCode;
  }

  public static HttpRespContent ofOk(String contentType, byte[] content) {
    return new HttpRespContent(HttpStatusCode.SC_OK, contentType, false, content);
  }

  public static HttpRespContent ofOk(String contentType, boolean base64, byte[] content) {
    return new HttpRespContent(HttpStatusCode.SC_OK, contentType, base64, content);
  }

  @Deprecated
  public static HttpRespContent ofError(int statusCode, String contentType, byte[] content) {
    return new HttpRespContent(statusCode, contentType, false, content);
  }

  @Deprecated
  public static HttpRespContent ofError(int statusCode, String contentType, boolean base64, byte[] content) {
    return new HttpRespContent(statusCode, contentType, base64, content);
  }

  public static HttpRespContent of(int statusCode, String contentType, byte[] content) {
    return new HttpRespContent(statusCode, contentType, false, content);
  }

  public static HttpRespContent of(int statusCode, String contentType, boolean base64, byte[] content) {
    return new HttpRespContent(statusCode, contentType, base64, content);
  }

  public boolean isOK() {
    return statusCode == HttpStatusCode.SC_OK;
  }

  public int getStatusCode() {
    return statusCode;
  }

  public String getContentType() {
    return contentType;
  }

  public boolean isBase64() {
    return base64;
  }

  public byte[] getContent() {
    return content;
  }
}
