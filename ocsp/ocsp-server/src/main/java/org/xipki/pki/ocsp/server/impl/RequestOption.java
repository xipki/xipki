/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.pki.ocsp.server.impl;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.xipki.common.InvalidConfException;
import org.xipki.common.util.IoUtil;
import org.xipki.pki.ocsp.server.impl.jaxb.CertCollectionType;
import org.xipki.pki.ocsp.server.impl.jaxb.CertCollectionType.Keystore;
import org.xipki.pki.ocsp.server.impl.jaxb.NonceType;
import org.xipki.pki.ocsp.server.impl.jaxb.RequestOptionType;
import org.xipki.pki.ocsp.server.impl.jaxb.RequestOptionType.CertpathValidation;
import org.xipki.pki.ocsp.server.impl.jaxb.RequestOptionType.HashAlgorithms;
import org.xipki.pki.ocsp.server.impl.jaxb.VersionsType;
import org.xipki.security.api.CertpathValidationModel;
import org.xipki.security.api.HashAlgoType;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

class RequestOption {
    static final Set<HashAlgoType> supportedHashAlgorithms = new HashSet<>();

    static {
        supportedHashAlgorithms.add(HashAlgoType.SHA1);
        supportedHashAlgorithms.add(HashAlgoType.SHA224);
        supportedHashAlgorithms.add(HashAlgoType.SHA256);
        supportedHashAlgorithms.add(HashAlgoType.SHA384);
        supportedHashAlgorithms.add(HashAlgoType.SHA512);
    }

    private final boolean supportsHttpGet;
    private final boolean signatureRequired;
    private final boolean validateSignature;

    private final int maxRequestSize;
    private final Collection<Integer> versions;
    private final boolean nonceRequired;
    private final int nonceMinLen;
    private final int nonceMaxLen;
    private final Set<HashAlgoType> hashAlgos;
    private final Set<CertWithEncoded> trustAnchors;
    private final Set<X509Certificate> certs;
    private final CertpathValidationModel certpathValidationModel;

    public RequestOption(
            final RequestOptionType conf)
    throws InvalidConfException {
        NonceType nonceConf = conf.getNonce();

        supportsHttpGet = conf.isSupportsHttpGet();
        signatureRequired = conf.isSignatureRequired();
        validateSignature = conf.isValidateSignature();

        int minLen = 4;
        int maxLen = 32;
        // Request nonce
        if (nonceConf != null) {
            nonceRequired = nonceConf.isRequired();
            if (nonceConf.getMinLen() != null) {
                minLen = nonceConf.getMinLen();
            }

            if (nonceConf.getMaxLen() != null) {
                maxLen = nonceConf.getMaxLen();
            }
        } else {
            nonceRequired = false;
        }

        int _maxSize = 0;
        if (conf.getMaxRequestSize() != null) {
            _maxSize = conf.getMaxRequestSize().intValue();
        }

        if (_maxSize < 255) {
            _maxSize = 4 * 1024; // 4 KB
        }
        this.maxRequestSize = _maxSize;

        this.nonceMinLen = minLen;
        this.nonceMaxLen = maxLen;

        // Request versions

        VersionsType versionsConf = conf.getVersions();
        if (versionsConf == null) {
            this.versions = null;
        } else {
            this.versions = new HashSet<>();
            this.versions.addAll(versionsConf.getVersion());
        }

        // Request hash algorithms
        hashAlgos = new HashSet<>();

        HashAlgorithms reqHashAlgosConf = conf.getHashAlgorithms();
        if (reqHashAlgosConf != null) {
            for (String token : reqHashAlgosConf.getAlgorithm()) {
                HashAlgoType algo = HashAlgoType.getHashAlgoType(token);
                if (algo != null && supportedHashAlgorithms.contains(algo)) {
                    hashAlgos.add(algo);
                } else {
                    throw new InvalidConfException("hash algorithm " + token + " is unsupported");
                }
            }
        } else {
            hashAlgos.addAll(supportedHashAlgorithms);
        }

        // certpath validiation
        CertpathValidation certpathConf = conf.getCertpathValidation();
        if (certpathConf == null) {
            if (validateSignature) {
                throw new InvalidConfException("certpathValidation is not specified");
            }
            trustAnchors = null;
            certs = null;
            certpathValidationModel = CertpathValidationModel.PKIX;
        } else {
            switch (certpathConf.getValidationModel()) {
            case CHAIN:
                certpathValidationModel = CertpathValidationModel.CHAIN;
                break;
            case PKIX:
                certpathValidationModel = CertpathValidationModel.PKIX;
                break;
            default:
                throw new RuntimeException("should not reach here, unknown ValidaitonModel "
                        + certpathConf.getValidationModel());
            } // end switch

            try {
                Set<X509Certificate> tmpCerts = getCerts(certpathConf.getTrustAnchors());
                trustAnchors = new HashSet<>(tmpCerts.size());
                for (X509Certificate m : tmpCerts) {
                    trustAnchors.add(new CertWithEncoded(m));
                }
            } catch (Exception e) {
                throw new InvalidConfException(
                        "error while initializing the trustAnchors: " + e.getMessage(), e);
            }

            CertCollectionType certsType = certpathConf.getCerts();
            if (certsType == null) {
                this.certs = null;
            } else {
                try {
                    this.certs = getCerts(certsType);
                } catch (Exception e) {
                    throw new InvalidConfException(
                            "error while initializing the certs: " + e.getMessage(), e);
                }
            }
        }

    }

    public Set<HashAlgoType> getHashAlgos() {
        return hashAlgos;
    }

    public boolean isSignatureRequired() {
        return signatureRequired;
    }

    public boolean isValidateSignature() {
        return validateSignature;
    }

    public boolean supportsHttpGet() {
        return supportsHttpGet;
    }

    public boolean isNonceRequired() {
        return nonceRequired;
    }

    public int getMaxRequestSize() {
        return maxRequestSize;
    }

    public int getNonceMinLen() {
        return nonceMinLen;
    }

    public int getNonceMaxLen() {
        return nonceMaxLen;
    }

    public boolean allows(
            final HashAlgoType hashAlgo) {
        return hashAlgos.contains(hashAlgo);
    }

    public CertpathValidationModel getCertpathValidationModel() {
        return certpathValidationModel;
    }

    public Set<CertWithEncoded> getTrustAnchors() {
        return trustAnchors;
    }

    public Set<X509Certificate> getCerts() {
        return certs;
    }

    public boolean isVersionAllowed(
            final Integer version) {
        return versions == null || versions.contains(version);
    }

    private Set<X509Certificate> getCerts(
            final CertCollectionType conf)
    throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        Set<X509Certificate> certs = new HashSet<>();

        if (conf.getKeystore() != null) {
            Keystore ksConf = conf.getKeystore();
            KeyStore trustStore = KeyStore.getInstance(ksConf.getType());
            InputStream is = null;

            String fileName = ksConf.getKeystore().getFile();
            if (fileName != null) {
                is = new FileInputStream(IoUtil.expandFilepath(fileName));
            } else {
                is = new ByteArrayInputStream(ksConf.getKeystore().getValue());
            }

            char[] password = (ksConf.getPassword() == null)
                    ? null
                    : ksConf.getPassword().toCharArray();
            trustStore.load(is, password);

            Enumeration<String> aliases = trustStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (trustStore.isCertificateEntry(alias)) {
                    certs.add((X509Certificate) trustStore.getCertificate(alias));
                }
            }
        } else if (conf.getDir() != null) {
            File dir = new File(conf.getDir());
            File[] files = dir.listFiles();
            for (File file : files) {
                if (file.exists() && file.isFile()) {
                    certs.add(X509Util.parseCert(file));
                }
            }
        } else {
            throw new RuntimeException("should not happen, neither keystore nor dir is defined");
        }

        return certs;
    }

}
