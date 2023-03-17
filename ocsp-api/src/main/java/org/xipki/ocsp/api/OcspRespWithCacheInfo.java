// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.api;

/**
 * OCSP response with {@link ResponseCacheInfo}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspRespWithCacheInfo {

  public static final class ResponseCacheInfo {

    private final long generatedAt;

    private Long nextUpdate;

    public ResponseCacheInfo(long generatedAt) {
      this.generatedAt = generatedAt;
    }

    public long getGeneratedAt() {
      return generatedAt;
    }

    public void setNextUpdate(Long nextUpdate) {
      this.nextUpdate = nextUpdate;
    }

    public Long getNextUpdate() {
      return nextUpdate;
    }

  } // class ResponseCacheInfo

  private final byte[] response;

  private final ResponseCacheInfo cacheInfo;

  public OcspRespWithCacheInfo(byte[] response, ResponseCacheInfo cacheInfo) {
    this.response = response;
    this.cacheInfo = cacheInfo;
  }

  public byte[] getResponse() {
    return response;
  }

  public ResponseCacheInfo getCacheInfo() {
    return cacheInfo;
  }

}
