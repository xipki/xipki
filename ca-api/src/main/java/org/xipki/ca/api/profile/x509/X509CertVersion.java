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

package org.xipki.ca.api.profile.x509;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public enum X509CertVersion {

    v1(1),
    v2(2),
    v3(3);

    private int versionNumber;

    X509CertVersion(final int versionNumber) {
        this.versionNumber = versionNumber;
    }

    public int versionNumber() {
        return versionNumber;
    }

    public static X509CertVersion forName(final String version) {
        ParamUtil.requireNonNull("version", version);

        for (X509CertVersion m : values()) {
            if (m.name().equalsIgnoreCase(version)) {
                return m;
            }
        }
        throw new IllegalArgumentException("invalid X509CertVersion " + version);
    }

    public static X509CertVersion forValue(final int versionNumber) {
        for (X509CertVersion m : values()) {
            if (m.versionNumber == versionNumber) {
                return m;
            }
        }
        throw new IllegalArgumentException("invalid X509CertVersion " + versionNumber);
    }

}
