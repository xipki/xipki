/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.x509.ExtendedPKIXBuilderParameters;
import org.xipki.ocsp.conf.jaxb.CertCollectionType;
import org.xipki.ocsp.conf.jaxb.CertCollectionType.Keystore;
import org.xipki.ocsp.conf.jaxb.NonceType;
import org.xipki.ocsp.conf.jaxb.RequestType;
import org.xipki.ocsp.conf.jaxb.RequestType.CertpathValidation;
import org.xipki.ocsp.conf.jaxb.RequestType.HashAlgorithms;
import org.xipki.security.common.HashAlgoType;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

class RequestOptions
{
    static final Set<HashAlgoType> supportedHashAlgorithms = new HashSet<>();

    static
    {
        supportedHashAlgorithms.add(HashAlgoType.SHA1);
        supportedHashAlgorithms.add(HashAlgoType.SHA224);
        supportedHashAlgorithms.add(HashAlgoType.SHA256);
        supportedHashAlgorithms.add(HashAlgoType.SHA384);
        supportedHashAlgorithms.add(HashAlgoType.SHA512);
    }

    private final boolean signatureRequired;
    private final boolean validateSignature;

    private final int maxRequestSize;
    private final boolean nonceRequired;
    private final int nonceMinLen;
    private final int nonceMaxLen;
    private final Set<HashAlgoType> hashAlgos;
    private final Set<TrustAnchor> trustAnchors;
    private final CertStore certs;
    private final int certpathValidationModel;

    public RequestOptions(RequestType conf)
    throws OcspResponderException
    {
        NonceType nonceConf = conf.getNonce();

        signatureRequired = conf.isSignatureRequired();
        validateSignature = conf.isValidateSignature();

        int minLen = 4;
        int maxLen = 32;
        // Request nonce
        if(nonceConf != null)
        {
            nonceRequired = nonceConf.isRequired();
            if(nonceConf.getMinLen() != null)
            {
                minLen = nonceConf.getMinLen();
            }

            if(nonceConf.getMaxLen() != null)
            {
                maxLen = nonceConf.getMaxLen();
            }
        }
        else
        {
            nonceRequired = false;
        }

        int _maxSize = 0;
        if(conf.getMaxRequestSize() != null)
        {
            _maxSize = conf.getMaxRequestSize().intValue();
        }

        if(_maxSize < 255)
        {
            _maxSize = 4 * 1024; // 4 KB
        }
        this.maxRequestSize = _maxSize;

        this.nonceMinLen = minLen;
        this.nonceMaxLen = maxLen;

        // Request hash algorithms
        hashAlgos = new HashSet<>();

        HashAlgorithms reqHashAlgosConf = conf.getHashAlgorithms();
        if(reqHashAlgosConf != null)
        {
            for(String token : reqHashAlgosConf.getAlgorithm())
            {
                HashAlgoType algo = HashAlgoType.getHashAlgoType(token);
                if(algo != null && supportedHashAlgorithms.contains(algo))
                {
                    hashAlgos.add(algo);
                }
                else
                {
                    throw new OcspResponderException("Hash algorithm " + token + " is unsupported");
                }
            }
        }
        else
        {
            hashAlgos.addAll(supportedHashAlgorithms);
        }

        // certpath validiation
        CertpathValidation certpathConf = conf.getCertpathValidation();
        if(certpathConf == null)
        {
            if(validateSignature)
            {
                throw new OcspResponderException("certpathValidation is not specified");
            }
            trustAnchors = null;
            certs = null;
            certpathValidationModel = ExtendedPKIXBuilderParameters.PKIX_VALIDITY_MODEL;
        }
        else
        {
            switch(certpathConf.getValidationModel())
            {
                case CHAIN:
                    certpathValidationModel = ExtendedPKIXBuilderParameters.CHAIN_VALIDITY_MODEL;
                    break;
                case PKIX:
                    certpathValidationModel = ExtendedPKIXBuilderParameters.PKIX_VALIDITY_MODEL;
                    break;
                default:
                    throw new RuntimeException("should not reach here");
            }
            try
            {
                Set<X509Certificate> certs = getCerts(certpathConf.getTrustAnchors());
                Set<TrustAnchor> _trustAnchors = new HashSet<TrustAnchor>();
                for(X509Certificate cert : certs)
                {
                    _trustAnchors.add(new TrustAnchor(cert, null));
                }
                this.trustAnchors = Collections.unmodifiableSet(_trustAnchors);
            }catch(Exception e)
            {
                throw new OcspResponderException("Error while initializing the trustAnchors: " + e.getMessage(), e);
            }

            CertCollectionType certsType = certpathConf.getCerts();
            if(certsType == null)
            {
                this.certs = null;
            }
            else
            {
                try
                {
                    CertStoreParameters csp = new CollectionCertStoreParameters(getCerts(certsType));
                    this.certs = CertStore.getInstance("Collection", csp, "BC");
                }catch(Exception e)
                {
                    throw new OcspResponderException("Error while initializing the certs: " + e.getMessage(), e);
                }
            }
        }

    }

    public Set<HashAlgoType> getHashAlgos()
    {
        return hashAlgos;
    }

    public boolean isSignatureRequired()
    {
        return signatureRequired;
    }

    public boolean isValidateSignature()
    {
        return validateSignature;
    }

    public boolean isNonceRequired()
    {
        return nonceRequired;
    }

    public int getMaxRequestSize()
    {
        return maxRequestSize;
    }

    public int getNonceMinLen()
    {
        return nonceMinLen;
    }

    public int getNonceMaxLen()
    {
        return nonceMaxLen;
    }

    public boolean allows(HashAlgoType hashAlgo)
    {
        return hashAlgos.contains(hashAlgo);
    }

    public int getCertpathValidationModel()
    {
        return certpathValidationModel;
    }

    public Set<TrustAnchor> getTrustAnchors()
    {
        return trustAnchors;
    }

    public CertStore getCerts()
    {
        return certs;
    }

    private Set<X509Certificate> getCerts(CertCollectionType conf)
    throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
    {
        Set<X509Certificate> certs = new HashSet<>();

        if(conf.getKeystore() != null)
        {
            Keystore ksConf = conf.getKeystore();
            KeyStore trustStore = KeyStore.getInstance(ksConf.getType());
            InputStream is = null;

            String uriS = ksConf.getUri();
            if(uriS != null)
            {
                URL uri = new URL(uriS);
                is = uri.openStream();
            }

            char[] password = ksConf.getPassword() == null ?
                    null : ksConf.getPassword().toCharArray();
            trustStore.load(is, password);

            Enumeration<String> aliases = trustStore.aliases();
            while(aliases.hasMoreElements())
            {
                String alias = aliases.nextElement();
                if(trustStore.isCertificateEntry(alias))
                {
                    certs.add((X509Certificate) trustStore.getCertificate(alias));
                }
            }
        }
        else if(conf.getDir() != null)
        {
            File dir = new File(conf.getDir());
            File[] files = dir.listFiles();
            for(File file : files)
            {
                if(file.exists() && file.isFile())
                {
                    certs.add(IoCertUtil.parseCert(file));
                }
            }
        }
        else
        {
            throw new RuntimeException("should not happen, neither keystore nor dir is defined");
        }

        return certs;
    }

}
