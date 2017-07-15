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

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.xipki.common.util.ParamUtil;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public enum HashAlgoType {

    SHA1(20, AlgorithmCode.SHA1, "1.3.14.3.2.26", "SHA1", "S1"),
    SHA224(28, AlgorithmCode.SHA224, "2.16.840.1.101.3.4.2.4", "SHA224", "S224"),
    SHA256(32, AlgorithmCode.SHA256, "2.16.840.1.101.3.4.2.1", "SHA256", "S256"),
    SHA384(48, AlgorithmCode.SHA384, "2.16.840.1.101.3.4.2.2", "SHA384", "S384"),
    SHA512(64, AlgorithmCode.SHA512, "2.16.840.1.101.3.4.2.3", "SHA512", "S512"),
    SHA3_224(28, AlgorithmCode.SHA3_224, "2.16.840.1.101.3.4.2.7", "SHA3-224", "S3-224"),
    SHA3_256(32, AlgorithmCode.SHA3_256, "2.16.840.1.101.3.4.2.8", "SHA3-256", "S3-256"),
    SHA3_384(48, AlgorithmCode.SHA3_384, "2.16.840.1.101.3.4.2.9", "SHA3-384", "S3-384"),
    SHA3_512(64, AlgorithmCode.SHA3_512, "2.16.840.1.101.3.4.2.10", "SHA3-512", "S3-512");

    private static final Map<String, HashAlgoType> map = new HashMap<>();

    private final int length;

    private final ASN1ObjectIdentifier oid;

    private final AlgorithmIdentifier algId;

    private final String name;

    private final String shortName;

    private final AlgorithmCode algorithmCode;

    private final byte[] encoded;

    static {
        for (HashAlgoType type : HashAlgoType.values()) {
            map.put(type.oid.getId(), type);
            map.put(type.name, type);
        }

        map.put("SHA-1", SHA1);
        map.put("SHA-224", SHA224);
        map.put("SHA-256", SHA256);
        map.put("SHA-384", SHA384);
        map.put("SHA-512", SHA512);
        map.put("SHA3224", SHA3_224);
        map.put("SHA3256", SHA3_256);
        map.put("SHA3384", SHA3_384);
        map.put("SHA3512", SHA3_512);
    }

    private HashAlgoType(final int length, final AlgorithmCode algorithmCode, final String oid,
            final String name, final String shortName) {
        this.length = length;
        this.algorithmCode = algorithmCode;
        this.oid = new ASN1ObjectIdentifier(oid).intern();
        this.algId = new AlgorithmIdentifier(this.oid, DERNull.INSTANCE);
        this.name = name;
        this.shortName = shortName;
        try {
            this.encoded = new ASN1ObjectIdentifier(oid).getEncoded();
        } catch (IOException ex) {
            throw new IllegalArgumentException("invalid oid: " + oid);
        }
    }

    public int length() {
        return length;
    }

    public AlgorithmCode algorithmCode() {
        return algorithmCode;
    }

    public ASN1ObjectIdentifier oid() {
        return oid;
    }

    public String getName() {
        return name;
    }

    public String getShortName() {
        return shortName;
    }

    public static HashAlgoType getHashAlgoType(final ASN1ObjectIdentifier oid) {
        ParamUtil.requireNonNull("oid", oid);
        for (HashAlgoType hashAlgo : values()) {
            if (hashAlgo.oid.equals(oid)) {
                return hashAlgo;
            }
        }
        return null;
    }

    public static HashAlgoType getHashAlgoType(final String nameOrOid) {
        return map.get(nameOrOid.toUpperCase());
    }

    public static HashAlgoType getNonNullHashAlgoType(final ASN1ObjectIdentifier oid) {
        HashAlgoType type = getHashAlgoType(oid);
        if (type == null) {
            throw new IllegalArgumentException("Unknown HashAlgo OID '" + oid.getId() + "'");
        }
        return type;
    }

    public static HashAlgoType getNonNullHashAlgoType(final String nameOrOid) {
        HashAlgoType type = getHashAlgoType(nameOrOid);
        if (type == null) {
            throw new IllegalArgumentException("Unknown HashAlgo OID/name '" + nameOrOid + "'");
        }
        return type;
    }

    public static HashAlgoType getInstanceForPkcs11HashMech(final long hashMech) {
        if (hashMech == PKCS11Constants.CKM_SHA_1) {
            return HashAlgoType.SHA1;
        } else if (hashMech == PKCS11Constants.CKM_SHA224) {
            return HashAlgoType.SHA224;
        } else if (hashMech == PKCS11Constants.CKM_SHA256) {
            return HashAlgoType.SHA256;
        } else if (hashMech == PKCS11Constants.CKM_SHA384) {
            return HashAlgoType.SHA384;
        } else if (hashMech == PKCS11Constants.CKM_SHA512) {
            return HashAlgoType.SHA512;
        } else if (hashMech == PKCS11Constants.CKM_SHA3_224) {
            return HashAlgoType.SHA3_224;
        } else if (hashMech == PKCS11Constants.CKM_SHA3_256) {
            return HashAlgoType.SHA3_256;
        } else if (hashMech == PKCS11Constants.CKM_SHA3_384) {
            return HashAlgoType.SHA3_384;
        } else if (hashMech == PKCS11Constants.CKM_SHA3_512) {
            return HashAlgoType.SHA3_512;
        } else {
            return null;
        }
    }

    public static HashAlgoType getInstanceForPkcs11MgfMech(final long hashMech) {
        if (hashMech == PKCS11Constants.CKG_MGF1_SHA1) {
            return HashAlgoType.SHA1;
        } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA224) {
            return HashAlgoType.SHA224;
        } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA256) {
            return HashAlgoType.SHA256;
        } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA384) {
            return HashAlgoType.SHA384;
        } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA512) {
            return HashAlgoType.SHA512;
        } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA3_224) {
            return HashAlgoType.SHA3_224;
        } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA3_256) {
            return HashAlgoType.SHA3_256;
        } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA3_384) {
            return HashAlgoType.SHA3_384;
        } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA3_512) {
            return HashAlgoType.SHA3_512;
        } else {
            return null;
        }
    }

    public static HashAlgoType getInstanceForEncoded(byte[] encoded) {
        for (HashAlgoType value : values()) {
            if (Arrays.equals(encoded, value.encoded)) {
                return value;
            }
        }
        return null;
    }

    public AlgorithmIdentifier algorithmIdentifier() {
        return algId;
    }

    public Digest createDigest() {
        switch (this) {
        case SHA1:
            return new SHA1Digest();
        case SHA224:
            return new SHA224Digest();
        case SHA256:
            return new SHA256Digest();
        case SHA384:
            return new SHA384Digest();
        case SHA512:
            return new SHA512Digest();
        case SHA3_224:
            return new SHA3Digest(224);
        case SHA3_256:
            return new SHA3Digest(256);
        case SHA3_384:
            return new SHA3Digest(384);
        case SHA3_512:
            return new SHA3Digest(512);
        default:
            throw new RuntimeException("should not reach here, unknown HashAlgoType " + name());
        }
    }

    public String hexHash(final byte[] data) {
        return HashCalculator.hexHash(this, data);
    }

    public String base64Hash(final byte[] data) {
        return HashCalculator.base64Hash(this, data);
    }

    public byte[] hash(final byte[] data) {
        return HashCalculator.hash(this, data);
    }
}
