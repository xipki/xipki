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

package org.xipki.pki.ca.server.impl.cmp;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.util.encoders.Hex;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.pki.ca.api.publisher.X509CertificateInfo;

/**
 * @author Lijun Liao
 */

class PendingCertificatePool {

    private static class MyEntry {

        private final BigInteger certReqId;

        private final long waitForConfirmTill;

        private final X509CertificateInfo certInfo;

        public MyEntry(
                final BigInteger certReqId,
                final long waitForConfirmTill,
                final X509CertificateInfo certInfo) {
            super();
            ParamUtil.assertNotNull("certReqId", certReqId);
            ParamUtil.assertNotNull("certInfo", certInfo);

            this.certReqId = certReqId;
            this.waitForConfirmTill = waitForConfirmTill;
            this.certInfo = certInfo;
        }

        @Override
        public int hashCode() {
            return certReqId.hashCode()
                    + 31 * 31 * (int) waitForConfirmTill
                    + 31 * certInfo.hashCode();
        }

        @Override
        public boolean equals(
                final Object b) {
            if (!(b instanceof MyEntry)) {
                return false;
            }

            MyEntry another = (MyEntry) b;
            return certReqId.equals(another.certReqId)
                    && certInfo.equals(another.certInfo);
        }

    } // class MyEntry

    private final Map<String, Set<MyEntry>> map = new ConcurrentHashMap<>();

    PendingCertificatePool() {
    }

    synchronized void addCertificate(
            final byte[] tid,
            final BigInteger certReqId,
            final X509CertificateInfo certInfo,
            final long waitForConfirmTill) {
        if (certInfo.isAlreadyIssued()) {
            return;
        }

        String hexTid = Hex.toHexString(tid);
        Set<MyEntry> entries = map.get(hexTid);
        if (entries == null) {
            entries = new HashSet<>();
            map.put(hexTid, entries);
        }

        MyEntry myEntry = new MyEntry(certReqId, waitForConfirmTill, certInfo);
        entries.add(myEntry);
    }

    synchronized X509CertificateInfo removeCertificate(
            final byte[] transactionId,
            final BigInteger certReqId,
            final byte[] certHash) {
        String hexTid = Hex.toHexString(transactionId);
        Set<MyEntry> entries = map.get(hexTid);
        if (entries == null) {
            return null;
        }

        MyEntry retEntry = null;
        for (MyEntry entry : entries) {
            if (certReqId.equals(entry.certReqId)) {
                retEntry = entry;
                break;
            }
        }

        if (retEntry != null) {
            entries.remove(retEntry);
        }

        if (CollectionUtil.isEmpty(entries)) {
            map.remove(hexTid);
        }

        return retEntry.certInfo;
    }

    synchronized Set<X509CertificateInfo> removeCertificates(
            final byte[] transactionId) {
        Set<MyEntry> entries = map.remove(Hex.toHexString(transactionId));
        if (entries == null) {
            return null;
        }

        Set<X509CertificateInfo> ret = new HashSet<>();
        for (MyEntry myEntry :entries) {
            ret.add(myEntry.certInfo);
        }
        return ret;
    }

    synchronized Set<X509CertificateInfo> removeConfirmTimeoutedCertificates() {
        if (CollectionUtil.isEmpty(map)) {
            return null;
        }

        long now = System.currentTimeMillis();

        Set<X509CertificateInfo> ret = new HashSet<>();

        for (String tid : map.keySet()) {
            Set<MyEntry> entries = map.get(tid);
            for (MyEntry entry : entries) {
                if (entry.waitForConfirmTill < now) {
                    ret.add(entry.certInfo);
                }
            }
        }
        return ret;
    }

}
