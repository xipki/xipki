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

import org.xipki.common.InvalidConfException;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.ocsp.server.impl.jaxb.CacheType;
import org.xipki.ocsp.server.impl.jaxb.EmbedCertsMode;
import org.xipki.ocsp.server.impl.jaxb.ResponseOptionType;
import org.xipki.security.HashAlgoType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class ResponseOption {

    private final boolean responderIdByName;

    private final boolean includeInvalidityDate;

    private final boolean includeRevReason;

    private final EmbedCertsMode embedCertsMode;

    private final boolean includeCerthash;

    private final HashAlgoType certHashAlgo;

    private final Long cacheMaxAge;

    ResponseOption(final ResponseOptionType conf) throws InvalidConfException {
        ParamUtil.requireNonNull("conf", conf);
        this.responderIdByName = getBoolean(conf.isResponderIdByName(), true);
        this.includeInvalidityDate = getBoolean(conf.isIncludeInvalidityDate(), true);
        this.includeRevReason = getBoolean(conf.isIncludeRevReason(), true);
        this.embedCertsMode = (conf.getEmbedCertsMode() == null) ?
                EmbedCertsMode.SIGNER : conf.getEmbedCertsMode();
        this.includeCerthash = getBoolean(conf.isIncludeCertHash(), false);
        CacheType cacheConf = conf.getCache();
        if (cacheConf != null && cacheConf.getCacheMaxAge() != null) {
            this.cacheMaxAge = cacheConf.getCacheMaxAge().longValue();
        } else {
            this.cacheMaxAge = null;
        }

        HashAlgoType tmpCertHashAlgo = null;
        String str = conf.getCerthashAlgorithm();
        if (str != null) {
            String token = str.trim();
            if (StringUtil.isNotBlank(token)) {
                HashAlgoType algo = HashAlgoType.getHashAlgoType(token);
                if (algo != null && RequestOption.SUPPORTED_HASH_ALGORITHMS.contains(algo)) {
                    tmpCertHashAlgo = algo;
                } else {
                    throw new InvalidConfException("hash algorithm " + token + " is unsupported");
                }
            }
        }
        this.certHashAlgo = tmpCertHashAlgo;
    }

    public boolean isResponderIdByName() {
        return responderIdByName;
    }

    public boolean isIncludeInvalidityDate() {
        return includeInvalidityDate;
    }

    public boolean isIncludeRevReason() {
        return includeRevReason;
    }

    public boolean isIncludeCerthash() {
        return includeCerthash;
    }

    public Long cacheMaxAge() {
        return cacheMaxAge;
    }

    public EmbedCertsMode embedCertsMode() {
        return embedCertsMode;
    }

    public HashAlgoType certHashAlgo() {
        return certHashAlgo;
    }

    private static boolean getBoolean(final Boolean bo, final boolean dflt) {
        return (bo == null) ? dflt : bo.booleanValue();
    }

}
