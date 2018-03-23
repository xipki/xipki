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

package org.xipki.ocsp.api;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspRespWithCacheInfo {

  public static final class ResponseCacheInfo {

    private final long thisUpdate;

    private Long nextUpdate;

    public ResponseCacheInfo(long thisUpdate) {
      this.thisUpdate = thisUpdate;
    }

    public long getThisUpdate() {
      return thisUpdate;
    }

    public void setNextUpdate(Long nextUpdate) {
      this.nextUpdate = nextUpdate;
    }

    public Long getNextUpdate() {
      return nextUpdate;
    }

  } // class ResponseCacheInfo

  private byte[] response;

  private ResponseCacheInfo cacheInfo;

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
