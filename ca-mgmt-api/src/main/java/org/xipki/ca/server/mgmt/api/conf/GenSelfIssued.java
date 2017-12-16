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

package org.xipki.ca.server.mgmt.api.conf;

import java.math.BigInteger;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

public class GenSelfIssued {

    private final String profile;

    private final byte[] csr;

    private final String certFilename;

    private final BigInteger serialNumber;

    public GenSelfIssued(final String profile, byte[] csr, final BigInteger serialNumber,
            final String certFilename) {
        this.profile = ParamUtil.requireNonBlank("profile", profile);
        this.csr = ParamUtil.requireNonNull("csr", csr);
        this.certFilename = certFilename;
        this.serialNumber = serialNumber;
    }

    public String profile() {
        return profile;
    }

    public byte[] csr() {
        return csr;
    }

    public String certFilename() {
        return certFilename;
    }

    public BigInteger serialNumber() {
        return serialNumber;
    }
}
