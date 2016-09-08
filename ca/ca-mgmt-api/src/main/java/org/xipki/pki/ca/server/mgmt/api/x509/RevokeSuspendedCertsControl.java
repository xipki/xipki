/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.server.mgmt.api.x509;

import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.CrlReason;
import org.xipki.pki.ca.api.profile.CertValidity;

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

    public CrlReason getTargetReason() {
        return targetReason;
    }

    public CertValidity getUnchangedSince() {
        return unchangedSince;
    }

    @Override
    public String toString() {
        ConfPairs pairs = new ConfPairs();
        pairs.putPair(KEY_REVOCATION_REASON, targetReason.getDescription());
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
