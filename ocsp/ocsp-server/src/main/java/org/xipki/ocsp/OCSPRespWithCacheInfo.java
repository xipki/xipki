/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp;

import org.bouncycastle.cert.ocsp.OCSPResp;

/**
 * @author Lijun Liao
 */

class OCSPRespWithCacheInfo
{
    final static class ResponseCacheInfo
    {
        private final long thisUpdate;
        private Long nextUpdate;

        ResponseCacheInfo(long thisUpdate)
        {
            this.thisUpdate = thisUpdate;
        }

        public long getThisUpdate()
        {
            return thisUpdate;
        }

        public void setNextUpdate(Long nextUpdate)
        {
            this.nextUpdate = nextUpdate;
        }

        public Long getNextUpdate()
        {
            return nextUpdate;
        }

    }

    private final OCSPResp response;
    private final ResponseCacheInfo cacheInfo;

    public OCSPRespWithCacheInfo(OCSPResp response, ResponseCacheInfo cacheInfo)
    {
        this.response = response;
        this.cacheInfo = cacheInfo;
    }

    public OCSPResp getResponse()
    {
        return response;
    }

    public ResponseCacheInfo getCacheInfo()
    {
        return cacheInfo;
    }

}
