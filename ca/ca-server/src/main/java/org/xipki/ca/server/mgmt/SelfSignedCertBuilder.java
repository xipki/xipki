/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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
import java.util.List;

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
import org.xipki.ca.common.CertValidity;
import org.xipki.ca.server.PublicCAInfo;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.ConfigurationException;
import org.xipki.common.IoCertUtil;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

class SelfSignedCertBuilder
{
    private static final Logger LOG = LoggerFactory.getLogger(SelfSignedCertBuilder.class);

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

        CertValidity validity = certProfile.getValidity();
        if(validity == null)
        {
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
                    "no validity specified in the profile " + certProfile.getName());
        }

        Date notAfter = validity.add(notBefore);

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
