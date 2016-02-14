/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.pki.scep.crypto;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public enum KeyUsage {

    digitalSignature (
            0, org.bouncycastle.asn1.x509.KeyUsage.digitalSignature, "digitalSignature"),
    contentCommitment (
            1, org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation,
            "contentCommitment", "nonRepudiation"),
    keyEncipherment (
            2, org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment, "keyEncipherment"),
    dataEncipherment (
            3, org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment, "dataEncipherment"),
    keyAgreement (
            4, org.bouncycastle.asn1.x509.KeyUsage.keyAgreement, "keyAgreement"),
    keyCertSign (
            5, org.bouncycastle.asn1.x509.KeyUsage.keyCertSign, "keyCertSign"),
    cRLSign (
            6, org.bouncycastle.asn1.x509.KeyUsage.cRLSign, "cRLSign"),
    encipherOnly (
            7, org.bouncycastle.asn1.x509.KeyUsage.encipherOnly, "encipherOnly"),
    decipherOnly (
            8, org.bouncycastle.asn1.x509.KeyUsage.decipherOnly, "decipherOnly");

    private int bit;

    private int bcUsage;

    private String[] names;

    KeyUsage(
            final int bit,
            final int bcUsage,
            final String... names) {
        this.bit = bit;
        this.bcUsage = bcUsage;
        this.names = names;
    }

    public int getBit() {
        return bit;
    }

    public int getBcUsage() {
        return bcUsage;
    }

    public String getName() {
        return names[0];
    }

    public static KeyUsage getKeyUsage(
            final String usage) {
        if (usage == null) {
            return null;
        }

        for (KeyUsage ku : KeyUsage.values()) {
            for (String name : ku.names) {
                if (name.equals(usage)) {
                    return ku;
                }
            }
        }

        return null;
    }

    public static KeyUsage getKeyUsage(
            final int bit) {
        for (KeyUsage ku : KeyUsage.values()) {
            if (ku.bit == bit) {
                return ku;
            }
        }

        return null;
    }

    public static KeyUsage getKeyUsageFromBcUsage(
            final int bcUsage) {
        for (KeyUsage ku : KeyUsage.values()) {
            if (ku.bcUsage == bcUsage) {
                return ku;
            }
        }

        return null;
    }

}
