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

package org.xipki.ca.dbtool.diffdb.io;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertsBundle {

    private Map<BigInteger, DbDigestEntry> certs;

    private List<BigInteger> serialNumbers;

    public CertsBundle(Map<BigInteger, DbDigestEntry> certs, List<BigInteger> serialNumbers) {
        this.certs = ParamUtil.requireNonEmpty("certs", certs);
        this.serialNumbers = ParamUtil.requireNonEmpty("serialNumbers", serialNumbers);
    }

    public Map<BigInteger, DbDigestEntry> certs() {
        return certs;
    }

    public List<BigInteger> serialNumbers() {
        return serialNumbers;
    }

}
