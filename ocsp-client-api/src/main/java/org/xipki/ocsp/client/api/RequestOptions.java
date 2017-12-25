/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ocsp.client.api;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RequestOptions {

    private static final Map<String, AlgorithmIdentifier> SIGALGS_MAP = new HashMap<>();

    static {
        String algoName = "SHA1withRSA";
        SIGALGS_MAP.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA256withRSA";
        SIGALGS_MAP.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA384withRSA";
        SIGALGS_MAP.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA512withRSA";
        SIGALGS_MAP.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA1withECDSA";
        SIGALGS_MAP.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA256withECDSA";
        SIGALGS_MAP.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA384withECDSA";
        SIGALGS_MAP.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA512withECDSA";
        SIGALGS_MAP.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA1withRSAandMGF1";
        SIGALGS_MAP.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA256withRSAandMGF1";
        SIGALGS_MAP.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA384withRSAandMGF1";
        SIGALGS_MAP.put(algoName.toUpperCase(), createAlgId(algoName));

        algoName = "SHA512withRSAandMGF1";
        SIGALGS_MAP.put(algoName.toUpperCase(), createAlgId(algoName));

    }

    private boolean signRequest;

    private boolean useNonce = true;

    private int nonceLen = 8;

    private boolean useHttpGetForRequest;

    private ASN1ObjectIdentifier hashAlgorithmId = NISTObjectIdentifiers.id_sha256;

    private List<AlgorithmIdentifier> preferredSignatureAlgorithms;

    public RequestOptions() {
    }

    public boolean isUseNonce() {
        return useNonce;
    }

    public void setUseNonce(final boolean useNonce) {
        this.useNonce = useNonce;
    }

    public int nonceLen() {
        return nonceLen;
    }

    public void setNonceLen(final int nonceLen) {
        this.nonceLen = ParamUtil.requireMin("nonceLen", nonceLen, 1);
    }

    public ASN1ObjectIdentifier hashAlgorithmId() {
        return hashAlgorithmId;
    }

    public void setHashAlgorithmId(final ASN1ObjectIdentifier hashAlgorithmId) {
        this.hashAlgorithmId = hashAlgorithmId;
    }

    public List<AlgorithmIdentifier> preferredSignatureAlgorithms() {
        return preferredSignatureAlgorithms;
    }

    public void setPreferredSignatureAlgorithms(
            final AlgorithmIdentifier[] preferredSignatureAlgorithms) {
        this.preferredSignatureAlgorithms = Arrays.asList(preferredSignatureAlgorithms);
    }

    public void setPreferredSignatureAlgorithms(final String[] preferredSignatureAlgoNames) {
        if (preferredSignatureAlgoNames == null || preferredSignatureAlgoNames.length == 0) {
            this.preferredSignatureAlgorithms = null;
            return;
        }

        for (String algoName : preferredSignatureAlgoNames) {
            AlgorithmIdentifier sigAlgId = SIGALGS_MAP.get(algoName.toUpperCase());
            if (sigAlgId == null) {
                // ignore it
                continue;
            }

            if (this.preferredSignatureAlgorithms == null) {
                this.preferredSignatureAlgorithms = new ArrayList<>(
                        preferredSignatureAlgoNames.length);
            }
            this.preferredSignatureAlgorithms.add(sigAlgId);
        }
    }

    public boolean isUseHttpGetForRequest() {
        return useHttpGetForRequest;
    }

    public void setUseHttpGetForRequest(final boolean useHttpGetForRequest) {
        this.useHttpGetForRequest = useHttpGetForRequest;
    }

    public boolean isSignRequest() {
        return signRequest;
    }

    public void setSignRequest(final boolean signRequest) {
        this.signRequest = signRequest;
    }

    private static AlgorithmIdentifier createAlgId(final String algoName) {
        ASN1ObjectIdentifier algOid = null;
        if ("SHA1withRSA".equalsIgnoreCase(algoName)) {
            algOid = PKCSObjectIdentifiers.sha1WithRSAEncryption;
        } else if ("SHA256withRSA".equalsIgnoreCase(algoName)) {
            algOid = PKCSObjectIdentifiers.sha256WithRSAEncryption;
        } else if ("SHA384withRSA".equalsIgnoreCase(algoName)) {
            algOid = PKCSObjectIdentifiers.sha384WithRSAEncryption;
        } else if ("SHA512withRSA".equalsIgnoreCase(algoName)) {
            algOid = PKCSObjectIdentifiers.sha512WithRSAEncryption;
        } else if ("SHA1withECDSA".equalsIgnoreCase(algoName)) {
            algOid = X9ObjectIdentifiers.ecdsa_with_SHA1;
        } else if ("SHA256withECDSA".equalsIgnoreCase(algoName)) {
            algOid = X9ObjectIdentifiers.ecdsa_with_SHA256;
        } else if ("SHA384withECDSA".equalsIgnoreCase(algoName)) {
            algOid = X9ObjectIdentifiers.ecdsa_with_SHA384;
        } else if ("SHA512withECDSA".equalsIgnoreCase(algoName)) {
            algOid = X9ObjectIdentifiers.ecdsa_with_SHA512;
        } else if ("SHA1withRSAandMGF1".equalsIgnoreCase(algoName)
                || "SHA256withRSAandMGF1".equalsIgnoreCase(algoName)
                || "SHA384withRSAandMGF1".equalsIgnoreCase(algoName)
                || "SHA512withRSAandMGF1".equalsIgnoreCase(algoName)) {
            algOid = PKCSObjectIdentifiers.id_RSASSA_PSS;
        } else {
            throw new RuntimeException("Unsupported algorithm " + algoName); // should not happen
        }

        ASN1Encodable params;
        if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algOid)) {
            ASN1ObjectIdentifier digestAlgOid = null;
            if ("SHA1withRSAandMGF1".equalsIgnoreCase(algoName)) {
                digestAlgOid = X509ObjectIdentifiers.id_SHA1;
            } else if ("SHA256withRSAandMGF1".equalsIgnoreCase(algoName)) {
                digestAlgOid = NISTObjectIdentifiers.id_sha256;
            } else if ("SHA384withRSAandMGF1".equalsIgnoreCase(algoName)) {
                digestAlgOid = NISTObjectIdentifiers.id_sha384;
            } else { // if ("SHA512withRSAandMGF1".equalsIgnoreCase(algoName))
                digestAlgOid = NISTObjectIdentifiers.id_sha512;
            }
            params = createPSSRSAParams(digestAlgOid);
        } else {
            params = DERNull.INSTANCE;
        }

        return new AlgorithmIdentifier(algOid, params);
    } // method createAlgId

    // CHECKSTYLE:SKIP
    public static RSASSAPSSparams createPSSRSAParams(final ASN1ObjectIdentifier digestAlgOid) {
        int saltSize;
        if (X509ObjectIdentifiers.id_SHA1.equals(digestAlgOid)) {
            saltSize = 20;
        } else if (NISTObjectIdentifiers.id_sha224.equals(digestAlgOid)) {
            saltSize = 28;
        } else if (NISTObjectIdentifiers.id_sha256.equals(digestAlgOid)) {
            saltSize = 32;
        } else if (NISTObjectIdentifiers.id_sha384.equals(digestAlgOid)) {
            saltSize = 48;
        } else if (NISTObjectIdentifiers.id_sha512.equals(digestAlgOid)) {
            saltSize = 64;
        } else {
            throw new RuntimeException("unknown digest algorithm " + digestAlgOid);
        }

        AlgorithmIdentifier digAlgId = new AlgorithmIdentifier(digestAlgOid, DERNull.INSTANCE);
        return new RSASSAPSSparams(digAlgId,
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, digAlgId),
                new ASN1Integer(saltSize), RSASSAPSSparams.DEFAULT_TRAILER_FIELD);
    } // method createPSSRSAParams

}
