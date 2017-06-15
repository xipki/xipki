/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.security;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public enum AlgorithmCode {
    // RSA PKCS1v1_5
    SHA1WITHRSA((byte) 0x01),
    SHA224WITHRSA((byte) 0x02),
    SHA256WITHRSA((byte) 0x03),
    SHA384WITHRSA((byte) 0x04),
    SHA512WITHRSA((byte) 0x05),
    SHA3_224WITHRSA((byte) 0x06),
    SHA3_256WITHRSA((byte) 0x07),
    SHA3_384WITHRSA((byte) 0x08),
    SHA3_512WITHRSA((byte) 0x09),

    // RSA and MGF1
    SHA1WITHRSAANDMGF1((byte) 0x11),
    SHA224WITHRSAANDMGF1((byte) 0x12),
    SHA256WITHRSAANDMGF1((byte) 0x13),
    SHA384WITHRSAANDMGF1((byte) 0x14),
    SHA512WITHRSAANDMGF1((byte) 0x15),
    SHA3_224WITHRSAANDMGF1((byte) 0x16),
    SHA3_256WITHRSAANDMGF1((byte) 0x17),
    SHA3_384WITHRSAANDMGF1((byte) 0x18),
    SHA3_512WITHRSAANDMGF1((byte) 0x19),

    // DSA
    SHA1WITHDSA((byte) 0x21),
    SHA224WITHDSA((byte) 0x22),
    SHA256WITHDSA((byte) 0x23),
    SHA384WITHDSA((byte) 0x24),
    SHA512WITHDSA((byte) 0x25),
    SHA3_224WITHDSA((byte) 0x26),
    SHA3_256WITHDSA((byte) 0x27),
    SHA3_384WITHDSA((byte) 0x28),
    SHA3_512WITHDSA((byte) 0x29),

    // ECDSA
    SHA1WITHECDSA((byte) 0x31),
    SHA224WITHECDSA((byte) 0x32),
    SHA256WITHECDSA((byte) 0x33),
    SHA384WITHECDSA((byte) 0x34),
    SHA512WITHECDSA((byte) 0x35),
    SHA3_224WITHECDSA((byte) 0x36),
    SHA3_256WITHECDSA((byte) 0x37),
    SHA3_384WITHECDSA((byte) 0x38),
    SHA3_512WITHECDSA((byte) 0x39),

    // PlainECDSA
    SHA1WITHPLAIN_ECDSA((byte) 0x41),
    SHA224WITHPLAIN_ECDSA((byte) 0x42),
    SHA256WITHPLAIN_ECDSA((byte) 0x43),
    SHA384WITHPLAIN_ECDSA((byte) 0x44),
    SHA512WITHPLAIN_ECDSA((byte) 0x45),

    // HMAC
    HMAC_SHA1((byte) 0x51),
    HMAC_SHA224((byte) 0x52),
    HMAC_SHA256((byte) 0x53),
    HMAC_SHA384((byte) 0x54),
    HMAC_SHA512((byte) 0x55),
    HMAC_SHA3_224((byte) 0x56),
    HMAC_SHA3_256((byte) 0x57),
    HMAC_SHA3_384((byte) 0x58),
    HMAC_SHA3_512((byte) 0x9),

    // Hash Algorithm
    SHA1((byte) 0xE1),
    SHA224((byte) 0xE2),
    SHA256((byte) 0xE3),
    SHA384((byte) 0xE4),
    SHA512((byte) 0xE5),
    SHA3_224((byte) 0xE6),
    SHA3_256((byte) 0xE7),
    SHA3_384((byte) 0xE8),
    SHA3_512((byte) 0xE9);

    private byte code;

    private AlgorithmCode(byte code) {
        this.code = code;
    }

    public byte getCode() {
        return code;
    }

}
