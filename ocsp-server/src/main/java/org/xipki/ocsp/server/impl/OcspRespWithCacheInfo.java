/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.ocsp.server.impl;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class OcspRespWithCacheInfo {

    static final class ResponseCacheInfo {

        private final long thisUpdate;

        private Long nextUpdate;

        ResponseCacheInfo(final long thisUpdate) {
            this.thisUpdate = thisUpdate;
        }

        public long thisUpdate() {
            return thisUpdate;
        }

        public void setNextUpdate(final Long nextUpdate) {
            this.nextUpdate = nextUpdate;
        }

        public Long nextUpdate() {
            return nextUpdate;
        }

    } // class ResponseCacheInfo

    private byte[] response;

    private ResponseCacheInfo cacheInfo;

    OcspRespWithCacheInfo(final byte[] response, final ResponseCacheInfo cacheInfo) {
        this.response = response;
        this.cacheInfo = cacheInfo;
    }

    public byte[] response() {
        return response;
    }

    public ResponseCacheInfo cacheInfo() {
        return cacheInfo;
    }

}
