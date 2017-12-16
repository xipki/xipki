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

package org.xipki.ca.server.mgmt.api.x509;

import org.xipki.ca.api.profile.CertValidity;
import org.xipki.common.ConfPairs;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.CrlReason;

/**
 * Example configuration
 *<pre>
 * revokeSuspendedCerts.enabled=&lt;true|false&gt;, \
 *   [revokeSuspendedCerts.targetReason=&lt;CRL reason&gt;,\
 *    revokeSuspendedCerts.unchangedSince=&lt;duration&gt;]
 *</pre>
 * where duration is of format &lt;n&gt;h, &lt;n&gt;d, &lt;n&gt;y.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RevokeSuspendedCertsControl {

    public static final String KEY_REVOCATION_ENABLED = "revokeSuspendedCerts.enabled";

    public static final String KEY_REVOCATION_REASON = "revokeSuspendedCerts.targetReason";

    public static final String KEY_UNCHANGED_SINCE = "revokeSuspendedCerts.unchangedSince";

    private final CrlReason targetReason;

    private final CertValidity unchangedSince;

    public RevokeSuspendedCertsControl(final CrlReason targetReason,
            final CertValidity unchangedSince) {
        this.targetReason = ParamUtil.requireNonNull("targetReason", targetReason);
        this.unchangedSince = ParamUtil.requireNonNull("unchangedSince", unchangedSince);

        switch (targetReason) {
        case AFFILIATION_CHANGED:
        case CESSATION_OF_OPERATION:
        case KEY_COMPROMISE:
        case PRIVILEGE_WITHDRAWN:
        case SUPERSEDED:
        case UNSPECIFIED:
            break;
        default:
            throw new IllegalArgumentException("invalid targetReason " + targetReason);
        }
    } // constructor

    public CrlReason targetReason() {
        return targetReason;
    }

    public CertValidity unchangedSince() {
        return unchangedSince;
    }

    @Override
    public String toString() {
        ConfPairs pairs = new ConfPairs();
        pairs.putPair(KEY_REVOCATION_REASON, targetReason.description());
        pairs.putPair(KEY_UNCHANGED_SINCE, unchangedSince.toString());
        return pairs.getEncoded();
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof RevokeSuspendedCertsControl)) {
            return false;
        }

        RevokeSuspendedCertsControl obj2 = (RevokeSuspendedCertsControl) obj;
        return (targetReason == obj2.targetReason) && (unchangedSince != obj2.unchangedSince);
    }

}
