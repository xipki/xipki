// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import org.bouncycastle.crypto.Xof;
import org.xipki.security.HashAlgo;
import org.xipki.security.XiSecurityException;
import org.xipki.util.Args;
import org.xipki.util.Hex;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * PKCS#1 utility class.
 *
 * @author Lijun Liao (xipki)
 * @since 5.3.14
 */
public class PKCS1Util {

    private static final Map<HashAlgo, byte[]> digestPkcsPrefix = new HashMap<>();

    static {
        addDigestPkcsPrefix(HashAlgo.SHA1,     "3021300906052b0e03021a05000414");
        addDigestPkcsPrefix(HashAlgo.SHA224,   "302d300d06096086480165030402040500041c");
        addDigestPkcsPrefix(HashAlgo.SHA256,   "3031300d060960864801650304020105000420");
        addDigestPkcsPrefix(HashAlgo.SHA384,   "3041300d060960864801650304020205000430");
        addDigestPkcsPrefix(HashAlgo.SHA512,   "3051300d060960864801650304020305000440");
        addDigestPkcsPrefix(HashAlgo.SHA3_224, "302d300d06096086480165030402070500041c");
        addDigestPkcsPrefix(HashAlgo.SHA3_256, "3031300d060960864801650304020805000420");
        addDigestPkcsPrefix(HashAlgo.SHA3_384, "3041300d060960864801650304020905000430");
        addDigestPkcsPrefix(HashAlgo.SHA3_512, "3051300d060960864801650304020a05000440");
    } // method static

    private static void addDigestPkcsPrefix(HashAlgo algo, String prefix) {
        digestPkcsPrefix.put(algo, Hex.decode(prefix));
    }

    public static byte[] EMSA_PKCS1_v1_5_encoding(byte[] hashValue, int modulusBigLength, HashAlgo hashAlgo)
        throws XiSecurityException {
        final int hashLen = Args.notNull(hashAlgo, "hashAlgo").getLength();
        Args.range(Args.notNull(hashValue, "hashValue").length, "hashValue.length", hashLen, hashLen);

        int blockSize = (modulusBigLength + 7) / 8;
        byte[] prefix = digestPkcsPrefix.get(hashAlgo);

        if (prefix.length + hashLen + 3 > blockSize) {
            throw new XiSecurityException("data too long (maximal " + (blockSize - 3)
                + " allowed): " + (prefix.length + hashLen));
        }

        byte[] block = new byte[blockSize];

        block[0] = 0x00;
        // type code 1
        block[1] = 0x01;

        int offset = 2;
        while (offset < block.length - prefix.length - hashLen - 1) {
            block[offset++] = (byte) 0xFF;
        }
        // mark the end of the padding
        block[offset++] = 0x00;

        System.arraycopy(prefix, 0, block, offset, prefix.length);
        offset += prefix.length;
        System.arraycopy(hashValue, 0, block, offset, hashValue.length);
        return block;
    } // method EMSA_PKCS1_v1_5_encoding

    public static byte[] EMSA_PKCS1_v1_5_encoding(byte[] encodedDigestInfo, int modulusBigLength)
            throws XiSecurityException {
        int msgLen = Args.notNull(encodedDigestInfo, "encodedDigestInfo").length;
        int blockSize = (modulusBigLength + 7) / 8;

        if (msgLen + 3 > blockSize) {
            throw new XiSecurityException("data too long (maximal " + (blockSize - 3) + " allowed): " + msgLen);
        }

        byte[] block = new byte[blockSize];

        block[0] = 0x00;
        // type code 1
        block[1] = 0x01;

        int offset = 2;
        while (offset < block.length - msgLen - 1) {
            block[offset++] = (byte) 0xFF;
        }
        // mark the end of the padding
        block[offset++] = 0x00;

        System.arraycopy(encodedDigestInfo, 0, block, offset, encodedDigestInfo.length);
        return block;
    } // method EMSA_PKCS1_v1_5_encoding

    public static byte[] EMSA_PSS_ENCODE(HashAlgo contentDigest, byte[] hashValue, HashAlgo mgfDigest,
                                         int saltLen, int modulusBitLength, SecureRandom random)
        throws XiSecurityException {
        if (contentDigest.isShake()) {
            if (mgfDigest != contentDigest) {
                throw new XiSecurityException("contentDigest != mgfDigest");
            }

            if (saltLen != contentDigest.getLength()) {
                throw new XiSecurityException("saltLen != " + contentDigest.getLength() + ": " + saltLen);
            }
        }

        final int hLen = contentDigest.getLength();
        final byte[] salt = new byte[saltLen];
        final byte[] mDash = new byte[8 + saltLen + hLen];
        final byte trailer = (byte) 0xBC;

        if (hashValue.length != hLen) {
            throw new XiSecurityException("hashValue.length is incorrect: " + hashValue.length + " != " + hLen);
        }

        int emBits = modulusBitLength - 1;
        if (emBits < (8 * hLen + 8 * saltLen + 9)) {
            throw new IllegalArgumentException("key too small for specified hash and salt lengths");
        }

        System.arraycopy(hashValue, 0, mDash, mDash.length - hLen - saltLen, hLen);

        random.nextBytes(salt);
        System.arraycopy(salt, 0, mDash, mDash.length - saltLen, saltLen);

        byte[] hv = contentDigest.hash(mDash);
        byte[] block = new byte[(emBits + 7) / 8];
        block[block.length - saltLen - 1 - hLen - 1] = 0x01;
        System.arraycopy(salt, 0, block, block.length - saltLen - hLen - 1, saltLen);

        int dbMaskLen = block.length - hLen - 1;
        byte[] dbMask = mgf(mgfDigest, hv, dbMaskLen);

        for (int i = 0; i != dbMaskLen; i++) {
            block[i] ^= dbMask[i];
        }

        block[0] &= (0xff >> ((block.length * 8) - emBits));

        System.arraycopy(hv, 0, block, block.length - hLen - 1, hLen);

        block[block.length - 1] = trailer;
        return block;
    } // method EMSA_PSS_ENCODE

    /**
     * <p>The decoding operation EMSA-PSS-Decode recovers the message hash from
     * an encoded message <code>EM</code> and compares it to the hash of
     * <code>M</code>.</p>
     *
     * @param mgfDigest The MGF digest.
     * @param mHash the byte sequence resulting from applying the message digest
     * algorithm Hash to the message <i>M</i>.
     * @param EM the <i>encoded message</i>, an octet string of length
     * emLen = CEILING(emBits/8).
     * @param sLen the length, in octets, of the expected salt.
     * @param modulusBitLength bit length of the RSA modulus.
     * @return true if the result of the verification was
     * <i>consistent</i> with the expected result; and false if the
     * result was <i>inconsistent</i>.
     * @exception IllegalArgumentException if an exception occurs.
     */
    public static boolean EMSA_PSS_DECODE(HashAlgo mgfDigest, byte[] mHash, byte[] EM, int sLen, int modulusBitLength) {
        if (sLen < 0) {
            throw new IllegalArgumentException("sLen");
        }

        int emBits = modulusBitLength - 1;
        int hLen = mgfDigest.getLength();

        // 1. If the length of M is greater than the input limitation for the hash
        //    function (2**61 ? 1 octets for SHA-1) then output 'inconsistent' and
        //    stop.
        // 2. Let mHash = Hash(M), an octet string of length hLen.
        if (hLen != mHash.length) {
            throw new IllegalArgumentException("wrong hash");
        }
        // 3. If emBits < 8.hLen + 8.sLen + 9, output 'decoding error' and stop.
        if (emBits < (8 * hLen + 8*sLen + 9)) {
            throw new IllegalArgumentException("decoding error");
        }
        int emLen = (emBits + 7) / 8;
        // 4. If the rightmost octet of EM does not have hexadecimal value bc,
        //    output 'inconsistent' and stop.
        if ((EM[EM.length - 1] & 0xFF) != 0xBC) {
            return false;
        }
        // 5. Let maskedDB be the leftmost emLen ? hLen ? 1 octets of EM, and let
        //    H be the next hLen octets.
        // 6. If the leftmost 8.emLen ? emBits bits of the leftmost octet in
        //    maskedDB are not all equal to zero, output 'inconsistent' and stop.
        if ((EM[0] & (0xFF << (8 - (8*emLen - emBits)))) != 0) {
            return false;
        }
        byte[] DB = new byte[emLen - hLen - 1];
        byte[] H = new byte[hLen];
        System.arraycopy(EM, 0, DB, 0, emLen - hLen - 1);
        System.arraycopy(EM, emLen - hLen - 1, H,  0, hLen);
        // 7. Let dbMask = MGF(H, emLen ? hLen ? 1).
        byte[] dbMask = mgf(mgfDigest, H, emLen - hLen - 1);
        // 8. Let DB = maskedDB XOR dbMask.
        int i;
        for (i = 0; i < DB.length; i++) {
            DB[i] = (byte)(DB[i] ^ dbMask[i]);
        }
        // 9. Set the leftmost 8.emLen ? emBits bits of DB to zero.
        DB[0] &= (0xFF >>> (8*emLen - emBits));
        // 10. If the emLen - hLen -sLen -2 leftmost octets of DB are not zero or
        //     if the octet at position emLen -hLen -sLen -1 is not equal to 0x01,
        //     output 'inconsistent' and stop.
        // IMPORTANT (rsn): this is an error in the specs, the index of the 0x01
        // byte should be emLen -hLen -sLen -2 and not -1! authors have been
        // advised
        for (i = 0; i < (emLen - hLen - sLen - 2); i++) {
            if (DB[i] != 0) {
                return false;
            }
        }
        if (DB[i] != 0x01) { // i == emLen -hLen -sLen -2
            return false;
        }
        // 11. Let salt be the last sLen octets of DB.
        byte[] salt = new byte[sLen];
        System.arraycopy(DB, DB.length - sLen, salt, 0, sLen);
        // 12. Let M0 = 00 00 00 00 00 00 00 00 || mHash || salt;
        //     M0 is an octet string of length 8 + hLen + sLen with eight initial
        //     zero octets.
        // 13. Let H0 = Hash(M0), an octet string of length hLen.
        byte[] H0 = mgfDigest.hash(new byte[8], mHash, salt);
        // 14. If H = H0, output 'consistent.' Otherwise, output 'inconsistent.'
        return Arrays.equals(H, H0);
    }

    public static byte[] getDigestPkcsPrefix(HashAlgo hashAlgo) {
        byte[] bytes = digestPkcsPrefix.get(hashAlgo);
        return (bytes == null) ? null : Arrays.copyOf(bytes, bytes.length);
    }

    public static byte[] RSAES_OAEP_ENCODE(byte[] M, int modulusBigLength, HashAlgo hashAlgo, SecureRandom random) {
        int k = (modulusBigLength + 7) / 8;
        int mLen = M.length;
        int hLen = hashAlgo.getLength();

        /*1.  Length checking:

        a.  If the length of L is greater than the input limitation
        for the hash function (2^61 - 1 octets for SHA-1), output
        "label too long" and stop.

        b.  If mLen > k - 2hLen - 2, output "message too long" and
        stop.
        */
        if (mLen > k - 2 * hLen - 2) {
            throw new IllegalArgumentException("message too long");
        }

        byte[] lHash = hashAlgo.hash(new byte[0]);
        byte[] PS = new byte[k - mLen - 2 * hLen - 2];

        byte[] DB = concat(lHash, PS, new byte[]{1}, M);
        byte[] seed = new byte[hLen];
        random.nextBytes(seed);
        byte[] dbMask = mgf1(hashAlgo, seed, k - hLen - 1);
        // f. Let maskedDB = DB \xor dbMask.
        byte[] maskedDB = xor(DB, dbMask);

        // g.  Let seedMask = MGF(maskedDB, hLen).
        byte[] seedMask = mgf1(hashAlgo, maskedDB, hLen);
        // h.  Let maskedSeed = seed \xor seedMask.
        byte[] maskedSeed = xor(seed, seedMask);

        // EM = 0x00 || maskedSeed || maskedDB
        return concat(new byte[]{0}, maskedSeed, maskedDB);
    }

    public static byte[] RSAES_OAEP_DECODE(byte[] EM, int modulusBigLength, HashAlgo hashAlgo) {
        int k = (modulusBigLength + 7) / 8;
        if (EM.length != k) {
            throw new IllegalArgumentException("EM.length != k");
        }

        int hLen = hashAlgo.getLength();

        if (EM[0] != 0) {
            throw new IllegalArgumentException("decryption error");
        }

        byte[] maskedSeed = Arrays.copyOfRange(EM, 1, 1 + hLen);
        byte[] maskedDB = Arrays.copyOfRange(EM, 1 + hLen, k);

        // c.  Let seedMask = MGF(maskedDB, hLen).
        byte[] seedMask = mgf1(hashAlgo, maskedDB, hLen);

        // d.  Let seed = maskedSeed \xor seedMask.
        byte[] seed = xor(maskedSeed, seedMask);

        //  e.  Let dbMask = MGF(seed, k - hLen - 1).
        byte[] dbMask = mgf1(hashAlgo, seed, k - hLen - 1);

        // f.  Let DB = maskedDB \xor dbMask.
        byte[] DB = xor(maskedDB, dbMask);

        byte[] lHash = hashAlgo.hash(new byte[0]);
        for (int i = 0; i < hLen; i++) {
            if (lHash[i] != DB[i]) {
                throw new IllegalArgumentException("decryption error");
            }
        }

        // find the split char 0x01
        int mOffset = hLen;
        for (; mOffset < DB.length; mOffset++) {
            if (DB[mOffset] == 1) {
                break;
            }
            if (DB[mOffset] != 0) {
                throw new IllegalArgumentException("decryption error");
            }
        }
        mOffset++;

        if (mOffset >= DB.length) {
            throw new IllegalArgumentException("decryption error");
        }

        return Arrays.copyOfRange(DB, mOffset, DB.length);
    }

    /**
     * mask generator function, as described in PKCS1v2.
     */
    private static byte[] mgf(HashAlgo mgfDigest, byte[] Z, int length) {
        if (mgfDigest.isShake()) {
            Xof xof = (Xof) mgfDigest.createDigest();
            xof.update(Z, 0, Z.length);
            byte[] res = new byte[length];
            xof.doFinal(res, 0, length);
            return res;
        } else {
            return mgf1(mgfDigest, Z, length);
        }
    }

    private static byte[] mgf1(HashAlgo mgfDigest, byte[] Z, int length) {
        int mgfhLen = mgfDigest.getLength();
        byte[] mask = new byte[length];
        int counter = 0;

        byte[] all = new byte[Z.length + 4];
        System.arraycopy(Z, 0, all, 0, Z.length);

        while (counter < (length / mgfhLen)) {
            ItoOSP(counter, all, Z.length);
            byte[] hashBuf = mgfDigest.hash(all);
            System.arraycopy(hashBuf, 0, mask, counter * mgfhLen, mgfhLen);
            counter++;
        }

        if ((counter * mgfhLen) < length) {
            ItoOSP(counter, all, Z.length);
            byte[] hashBuf = mgfDigest.hash(all);
            int offset = counter * mgfhLen;
            System.arraycopy(hashBuf, 0, mask, offset, mask.length - offset);
        }

        return mask;
    } // method maskGeneratorFunction1

    /**
     * int to octet string.
     */
    private static void ItoOSP(int i, byte[] sp, int spOffset) {
        sp[spOffset    ] = (byte)(i >>> 24);
        sp[spOffset + 1] = (byte)(i >>> 16);
        sp[spOffset + 2] = (byte)(i >>> 8);
        sp[spOffset + 3] = (byte)(i);
    }

    private static byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) {
            throw new IllegalArgumentException("a.length != b.length");
        }

        byte[] rv = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            rv[i] = (byte) (a[i] ^ b[i]);
        }
        return rv;
    }

    private static byte[] concat(byte[]... byteArrays) {
        int len = 0;
        for (byte[] ba : byteArrays) {
            len += ba.length;
        }

        byte[] rv = new byte[len];
        int offset = 0;
        for (byte[] ba : byteArrays) {
            System.arraycopy(ba, 0, rv, offset, ba.length);
            offset += ba.length;
        }

        return rv;
    }

}
