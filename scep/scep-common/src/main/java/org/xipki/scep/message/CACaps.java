/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.scep.message;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.StringTokenizer;

import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.scep.crypto.HashAlgoType;
import org.xipki.scep.transaction.CACapability;

/**
 * @author Lijun Liao
 */

public class CACaps {
    private static final Logger LOG = LoggerFactory.getLogger(CACaps.class);

    private byte[] bytes;
    private final Set<CACapability> capabilities;

    public CACaps() {
        this.capabilities = new HashSet<CACapability>();
    }

    public CACaps(
            final Set<CACapability> capabilities) {
        if (capabilities == null) {
            this.capabilities = new HashSet<CACapability>();
        } else {
            this.capabilities = new HashSet<CACapability>(capabilities);
        }
        refresh();
    }

    public Set<CACapability> getCapabilities() {
        return Collections.unmodifiableSet(capabilities);
    }

    public void removeCapabilities(
            final CACaps caCaps) {
        this.capabilities.retainAll(caCaps.capabilities);
        refresh();
    }

    public void addCapability(
            final CACapability cap) {
        if (cap != null) {
            capabilities.add(cap);
            refresh();
        }
    }

    public void removeCapability(
            final CACapability cap) {
        if (cap != null) {
            capabilities.remove(cap);
            refresh();
        }
    }

    public boolean containsCapability(
            final CACapability cap) {
        return capabilities.contains(cap);
    }

    public static CACaps getInstance(
            final String scepMessage) {
        CACaps ret = new CACaps();
        if (scepMessage == null || scepMessage.isEmpty()) {
            return ret;
        }

        StringTokenizer st = new StringTokenizer(scepMessage, "\r\n");

        while (st.hasMoreTokens()) {
            String m = st.nextToken();
            CACapability cap = CACapability.valueForText(m);
            if (cap == null) {
                LOG.warn("ignore unknown CACap '{}'", m);
            } else {
                ret.addCapability(cap);
            }
        }
        return ret;
    }

    @Override
    public String toString() {
        return toScepMessage();
    }

    @Override
    public int hashCode() {
        return toScepMessage().hashCode();
    }

    public String toScepMessage() {
        if (capabilities.isEmpty()) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (CACapability cap : capabilities) {
            sb.append(cap.getText()).append("\n");
        }
        sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

    public boolean supportsPost() {
        return capabilities.contains(CACapability.POSTPKIOperation);
    }

    public HashAlgoType getMostSecureHashAlgo() {
        if (capabilities.contains(CACapability.SHA512)) {
            return HashAlgoType.SHA512;
        } else if (capabilities.contains(CACapability.SHA256)) {
            return HashAlgoType.SHA256;
        } else if (capabilities.contains(CACapability.SHA1)) {
            return HashAlgoType.SHA1;
        } else {
            return HashAlgoType.MD5;
        }
    }

    private void refresh() {
        if (capabilities != null) {
            this.bytes = toString().getBytes();
        }
    }

    @Override
    public boolean equals(
            final Object other) {
        if (!(other instanceof CACaps)) {
            return false;
        }

        CACaps b = (CACaps) other;
        return capabilities.equals(b.capabilities);
    }

    public byte[] getBytes() {
        return Arrays.clone(bytes);
    }
}
