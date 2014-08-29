/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.profile.ExtensionOccurrence;
import org.xipki.ca.api.profile.ExtensionTuple;
import org.xipki.ca.api.profile.ExtensionTuples;
import org.xipki.ca.api.profile.SubjectInfo;
import org.xipki.ca.api.profile.X509Util;
import org.xipki.ca.common.BadCertTemplateException;
import org.xipki.ca.common.CertProfileException;
import org.xipki.ca.server.mgmt.api.PublicCAInfo;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.ConfigurationException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.StringUtil;

/**
 * @author Lijun Liao
 */

class SelfSignedCertBuilder
{
    private static final Logger LOG = LoggerFactory.getLogger(SelfSignedCertBuilder.class);

    private static long DAY = 24L * 60 * 60 * 1000;

    static class GenerateSelfSignedResult
    {
        private final String signerConf;
        private final X509Certificate cert;

        GenerateSelfSignedResult(String signerConf, X509Certificate cert)
        {
            this.signerConf = signerConf;
            this.cert = cert;
        }

        String getSignerConf()
        {
            return signerConf;
        }

        X509Certificate getCert()
        {
            return cert;
        }
    }

    public static GenerateSelfSignedResult generateSelfSigned(
            SecurityFactory securityFactory,
            String signerType,
            String signerConf,
            IdentifiedCertProfile certProfile,
            String subject,
            long serialNumber,
            List<String> ocspUris,
            List<String> crlUris,
            List<String> deltaCrlUris)
    throws OperationException, ConfigurationException
    {
        if("pkcs12".equalsIgnoreCase(signerType) || "jks".equalsIgnoreCase(signerType))
        {
            CmpUtf8Pairs keyValues = new CmpUtf8Pairs(signerConf);
            String keystoreConf = keyValues.getValue("keystore");
            if(keystoreConf == null)
            {
                throw new ConfigurationException("required parameter 'keystore', for types PKCS12 and JKS, is not specified");
            }
            if(keystoreConf.startsWith("generate:"))
            {
                String keyLabel = keyValues.getValue("key-label");
                char[] password = keyValues.getValue("password").toCharArray();
                Map<String, String> keyStoreKeyValues = keyValues(
                        keystoreConf.substring("generate:".length()), ";");

                String keyType = keyStoreKeyValues.get("keytype");

                byte[] keystoreBytes = null;
                if("RSA".equalsIgnoreCase(keyType))
                {
                    String s = keyStoreKeyValues.get("keysize");
                    if(s == null)
                    {
                        throw new ConfigurationException("no keysize is specified");
                    }
                    int keysize = Integer.parseInt(s);
                    s = keyStoreKeyValues.get("exponent");
                    BigInteger exponent = (s == null) ? BigInteger.valueOf(65535) : new BigInteger(s);

                    try
                    {
                        keystoreBytes = securityFactory.generateSelfSignedRSAKeyStore(BigInteger.ONE,
                                subject, signerType, password, keyLabel, keysize, exponent);
                    } catch (Exception e)
                    {
                        throw new OperationException(ErrorCode.System_Failure, e.getMessage());
                    }
                }
                else
                {
                    throw new ConfigurationException("Unsupported keytype " + keyType);
                }

                keystoreConf = "base64:" + Base64.toBase64String(keystoreBytes);
                keyValues.putUtf8Pair("keystore", keystoreConf);

                signerConf = keyValues.getEncoded();
            }
            // generate the key first if not set
        }

        ConcurrentContentSigner signer;
        try
        {
            signer = securityFactory.createSigner(signerType, signerConf, (X509Certificate[]) null);
        } catch (SignerException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getClass().getName() + ": " + e.getMessage());
        }

        // this certificate is the dummy one which can be considered only as public key container
        Certificate bcCert;
        try
        {
            bcCert = Certificate.getInstance(signer.getCertificate().getEncoded());
        } catch (Exception e)
        {
            throw new OperationException(ErrorCode.System_Failure, "Could not reparse certificate: " + e.getMessage());
        }
        SubjectPublicKeyInfo publicKeyInfo = bcCert.getSubjectPublicKeyInfo();

        X509Certificate newCert = generateCertificate(
                signer, certProfile, new X500Name(subject), serialNumber, publicKeyInfo,
                ocspUris, crlUris, deltaCrlUris);

        return new GenerateSelfSignedResult(signerConf, newCert);
    }

    private static X509Certificate generateCertificate(
            ConcurrentContentSigner signer,
            IdentifiedCertProfile certProfile,
            X500Name requestedSubject,
            long serialNumber,
            SubjectPublicKeyInfo publicKeyInfo,
            List<String> ocspUris,
            List<String> crlUris,
            List<String> deltaCrlUris)
    throws OperationException
    {
        publicKeyInfo = IoCertUtil.toRfc3279Style(publicKeyInfo);

        try
        {
            certProfile.checkPublicKey(publicKeyInfo);
        } catch (BadCertTemplateException e)
        {
            LOG.warn("certProfile.checkPublicKey", e);
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, e.getMessage());
        }

        SubjectInfo subjectInfo;
        // subject
        try
        {
            subjectInfo = certProfile.getSubject(requestedSubject);
        }catch(CertProfileException e)
        {
            throw new OperationException(ErrorCode.System_Failure, "exception in cert profile " + certProfile.getName());
        } catch (BadCertTemplateException e)
        {
            LOG.warn("certProfile.getSubject", e);
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, e.getMessage());
        }

        Date notBefore = certProfile.getNotBefore(null);
        if(notBefore == null)
        {
            notBefore = new Date();
        }

        Integer validity = certProfile.getValidity();
        if(validity == null)
        {
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
                    "no validity specified in the profile " + certProfile.getName());
        }

        Date notAfter = new Date(notBefore.getTime() + DAY * validity);

        X500Name grantedSubject = subjectInfo.getGrantedSubject();

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                grantedSubject,
                BigInteger.valueOf(serialNumber),
                notBefore,
                notAfter,
                grantedSubject,
                publicKeyInfo);

        PublicCAInfo publicCaInfo = new PublicCAInfo(
                null, ocspUris, crlUris, null, deltaCrlUris);

        try
        {
            addExtensions(
                    certBuilder,
                    certProfile,
                    requestedSubject,
                    grantedSubject,
                    publicKeyInfo,
                    publicCaInfo,
                    BigInteger.valueOf(serialNumber));

            ContentSigner contentSigner = signer.borrowContentSigner();

            Certificate bcCert;
            try
            {
                bcCert = certBuilder.build(contentSigner).toASN1Structure();
            }finally
            {
                signer.returnContentSigner(contentSigner);
            }

            byte[] encodedCert = bcCert.getEncoded();

            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encodedCert));
        } catch (BadCertTemplateException e)
        {
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, e.getMessage());
        } catch (NoIdleSignerException | CertificateException | IOException | CertProfileException |
                NoSuchAlgorithmException | NoSuchProviderException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getClass().getName() + ": " + e.getMessage());
        }
    }

    private static String addExtensions(
            X509v3CertificateBuilder certBuilder,
            IdentifiedCertProfile profile,
            X500Name requestedSubject,
            X500Name subject,
            SubjectPublicKeyInfo requestedPublicKeyInfo,
            PublicCAInfo publicCaInfo,
            BigInteger serialNumber)
    throws CertProfileException, IOException, BadCertTemplateException, NoSuchAlgorithmException
    {
        // SubjectKeyIdentifier
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] skiValue = sha1.digest(requestedPublicKeyInfo.getPublicKeyData().getBytes());

        ExtensionOccurrence extOccurrence = profile.getOccurenceOfSubjectKeyIdentifier();
        if(extOccurrence != null)
        {
            SubjectKeyIdentifier value = new SubjectKeyIdentifier(skiValue);
            certBuilder.addExtension(Extension.subjectKeyIdentifier, extOccurrence.isCritical(), value);
        }

        // Authority key identifier
        extOccurrence = profile.getOccurenceOfAuthorityKeyIdentifier();
        if(extOccurrence != null)
        {
            AuthorityKeyIdentifier value;
            if(profile.includeIssuerAndSerialInAKI())
            {
                GeneralNames caSubject = new GeneralNames(new GeneralName(subject));
                value = new AuthorityKeyIdentifier(skiValue, caSubject, serialNumber);
            }
            else
            {
                value = new AuthorityKeyIdentifier(skiValue);
            }
            certBuilder.addExtension(Extension.authorityKeyIdentifier, extOccurrence.isCritical(), value);
        }

        // AuthorityInfoAccess
        extOccurrence = profile.getOccurenceOfAuthorityInfoAccess();
        if(extOccurrence != null)
        {
            AuthorityInformationAccess aia = X509Util.createAuthorityInformationAccess(publicCaInfo.getOcspUris());
            if(aia == null)
            {
                if(extOccurrence.isRequired())
                {
                    throw new CertProfileException("Could not add required extension authorityInfoAccess");
                }
            }
            else
            {
                certBuilder.addExtension(Extension.authorityInfoAccess, extOccurrence.isCritical(), aia);
            }
        }

        // CRLDistributionPoints
        extOccurrence = profile.getOccurenceOfCRLDistributinPoints();
        if(extOccurrence != null)
        {
            CRLDistPoint crlDistPoint = X509Util.createCRLDistributionPoints(publicCaInfo.getCrlUris(),
                    null, null);
            if(crlDistPoint == null)
            {
                if(extOccurrence.isRequired())
                {
                    throw new CertProfileException("Could not add required extension CRLDistributionPoints");
                }
            }
            else
            {
                certBuilder.addExtension(Extension.cRLDistributionPoints, extOccurrence.isCritical(), crlDistPoint);
            }
        }

        // FreshestCRL
        extOccurrence = profile.getOccurenceOfFreshestCRL();
        if(extOccurrence != null)
        {
            CRLDistPoint deltaCrlDistPoint = X509Util.createCRLDistributionPoints(publicCaInfo.getDeltaCrlUris(),
                    null, null);
            if(deltaCrlDistPoint == null)
            {
                if(extOccurrence.isRequired())
                {
                    throw new CertProfileException("Could not add required extension freshestCRL");
                }
            }
            else
            {
                certBuilder.addExtension(Extension.freshestCRL, extOccurrence.isCritical(), deltaCrlDistPoint);
            }
        }

        ExtensionTuples extensionTuples = profile.getExtensions(requestedSubject, null);

        for(ExtensionTuple extension : extensionTuples.getExtensions())
        {
            certBuilder.addExtension(extension.getType(), extension.isCritical(), extension.getValue());
        }

        return extensionTuples.getWarning();
    }

    private static Map<String, String> keyValues(String conf, String seperator)
    {
        Map<String, String> ret = new HashMap<>();
        List<String> tokens = StringUtil.split(conf, seperator);

        for(String token : tokens)
        {
            int idx = token.indexOf('=');
            if(idx <= 0 || idx == token.length()-1)
            {
                continue;
            }

            String tokenKey = token.substring(0, idx).trim();
            String tokenValue = token.substring(idx+1).trim();
            if("NULL".equalsIgnoreCase(tokenValue))
            {
                tokenValue = null;
            }
            ret.put(tokenKey, tokenValue);
        }

        return ret;
    }

    public static AsymmetricKeyParameter generatePublicKeyParameter(
            PublicKey key)
    throws InvalidKeyException
    {
        if (key instanceof RSAPublicKey)
        {
            RSAPublicKey k = (RSAPublicKey)key;
            return new RSAKeyParameters(false, k.getModulus(), k.getPublicExponent());
        }
        else if(key instanceof ECPublicKey)
        {
            return ECUtil.generatePublicKeyParameter(key);
        }
        else if(key instanceof DSAPublicKey)
        {
            return DSAUtil.generatePublicKeyParameter(key);
        }
        else
        {
            throw new InvalidKeyException("unknown key " + key.getClass().getName());
        }
    }

}
