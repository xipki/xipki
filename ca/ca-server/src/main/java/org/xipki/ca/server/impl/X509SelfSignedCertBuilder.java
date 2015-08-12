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

package org.xipki.ca.server.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.operator.ContentSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.CertprofileException;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.x509.SubjectInfo;
import org.xipki.common.InvalidConfException;
import org.xipki.common.util.CollectionUtil;
import org.xipki.security.api.CmpUtf8Pairs;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

class X509SelfSignedCertBuilder
{
    private static final Logger LOG = LoggerFactory.getLogger(X509SelfSignedCertBuilder.class);

    static class GenerateSelfSignedResult
    {
        private final String signerConf;
        private final X509Certificate cert;

        GenerateSelfSignedResult(
                final String signerConf,
                final X509Certificate cert)
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
            final SecurityFactory securityFactory,
            final String signerType,
            final String signerConf,
            final IdentifiedX509Certprofile certprofile,
            final CertificationRequest p10Request,
            final long serialNumber,
            final List<String> cacertUris,
            final List<String> ocspUris,
            final List<String> crlUris,
            final List<String> deltaCrlUris)
    throws OperationException, InvalidConfException
    {
        if(securityFactory.verifyPOPO(p10Request) == false)
        {
            throw new InvalidConfException("could not validate POP for the pkcs#10 requst");
        }

        if("pkcs12".equalsIgnoreCase(signerType) || "jks".equalsIgnoreCase(signerType))
        {
            CmpUtf8Pairs keyValues = new CmpUtf8Pairs(signerConf);
            String keystoreConf = keyValues.getValue("keystore");
            if(keystoreConf == null)
            {
                throw new InvalidConfException("required parameter 'keystore', for types PKCS12 and JKS, is not specified");
            }
        }

        ConcurrentContentSigner signer;
        try
        {
            List<String[]> signerConfs = CAManagerImpl.splitCASignerConfs(signerConf);
            List<String> restrictedSigAlgos = certprofile.getSignatureAlgorithms();

            String thisSignerConf = null;
            if(CollectionUtil.isEmpty(restrictedSigAlgos))
            {
                thisSignerConf = signerConfs.get(0)[1];
            }
            else
            {
                for(String algo : restrictedSigAlgos)
                {
                    for(String[] m : signerConfs)
                    {
                        if(m[0].equals(algo))
                        {
                            thisSignerConf = m[1];
                            break;
                        }
                    }

                    if(thisSignerConf != null)
                    {
                        break;
                    }
                }
            }

            if(thisSignerConf == null)
            {
                throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                        "CA does not support any signature algorithm restricted by the cert profile");
            }

            signer = securityFactory.createSigner(signerType, thisSignerConf, (X509Certificate[]) null);
        } catch (SignerException e)
        {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getClass().getName() + ": " + e.getMessage());
        }

        // this certificate is the dummy one which can be considered only as public key container
        Certificate bcCert;
        try
        {
            bcCert = Certificate.getInstance(signer.getCertificate().getEncoded());
        } catch (Exception e)
        {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, "could not reparse certificate: " + e.getMessage());
        }
        SubjectPublicKeyInfo publicKeyInfo = bcCert.getSubjectPublicKeyInfo();

        X509Certificate newCert = generateCertificate(
                signer, certprofile, p10Request, serialNumber, publicKeyInfo,
                cacertUris, ocspUris, crlUris, deltaCrlUris);

        return new GenerateSelfSignedResult(signerConf, newCert);
    }

    private static X509Certificate generateCertificate(
            final ConcurrentContentSigner signer,
            final IdentifiedX509Certprofile certprofile,
            final CertificationRequest p10Request,
            final long serialNumber,
            SubjectPublicKeyInfo publicKeyInfo,
            final List<String> cacertUris,
            final List<String> ocspUris,
            final List<String> crlUris,
            final List<String> deltaCrlUris)
    throws OperationException
    {
        try
        {
            publicKeyInfo = X509Util.toRfc3279Style(publicKeyInfo);
        } catch (InvalidKeySpecException e)
        {
            LOG.warn("SecurityUtil.toRfc3279Style", e);
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, e.getMessage());
        }

        try
        {
            certprofile.checkPublicKey(publicKeyInfo);
        } catch (BadCertTemplateException e)
        {
            LOG.warn("certprofile.checkPublicKey", e);
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, e.getMessage());
        }

        X500Name requestedSubject = p10Request.getCertificationRequestInfo().getSubject();

        SubjectInfo subjectInfo;
        // subject
        try
        {
            subjectInfo = certprofile.getSubject(requestedSubject);
        }catch(CertprofileException e)
        {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, "exception in cert profile " + certprofile.getName());
        } catch (BadCertTemplateException e)
        {
            LOG.warn("certprofile.getSubject", e);
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, e.getMessage());
        }

        Date notBefore = certprofile.getNotBefore(null);
        if(notBefore == null)
        {
            notBefore = new Date();
        }

        CertValidity validity = certprofile.getValidity();
        if(validity == null)
        {
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
                    "no validity specified in the profile " + certprofile.getName());
        }

        Date notAfter = validity.add(notBefore);

        X500Name grantedSubject = subjectInfo.getGrantedSubject();

        BigInteger _serialNumber = BigInteger.valueOf(serialNumber);
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                grantedSubject,
                _serialNumber,
                notBefore,
                notAfter,
                grantedSubject,
                publicKeyInfo);

        PublicCAInfo publicCaInfo = new PublicCAInfo(
                grantedSubject, _serialNumber, null, null,
                cacertUris, ocspUris, crlUris, deltaCrlUris);

        Extensions extensions = null;
        ASN1Set attrs = p10Request.getCertificationRequestInfo().getAttributes();
        for(int i = 0; i < attrs.size(); i++)
        {
            Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
            if(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType()))
            {
                extensions = Extensions.getInstance(attr.getAttributeValues()[0]);
            }
        }

        try
        {
            addExtensions(
                    certBuilder,
                    certprofile,
                    requestedSubject,
                    extensions,
                    publicKeyInfo,
                    publicCaInfo,
                    notBefore,
                    notAfter);

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
        } catch (NoIdleSignerException | CertificateException | IOException | CertprofileException |
                NoSuchAlgorithmException | NoSuchProviderException e)
        {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getClass().getName() + ": " + e.getMessage());
        }
    }

    private static void addExtensions(
            final X509v3CertificateBuilder certBuilder,
            final IdentifiedX509Certprofile profile,
            final X500Name requestedSubject,
            final Extensions extensions,
            final SubjectPublicKeyInfo requestedPublicKeyInfo,
            final PublicCAInfo publicCaInfo,
            final Date notBefore,
            final Date notAfter)
    throws CertprofileException, IOException, BadCertTemplateException, NoSuchAlgorithmException
    {
        ExtensionValues extensionTuples = profile.getExtensions(
                requestedSubject, extensions, requestedPublicKeyInfo,
                publicCaInfo, null, notBefore, notAfter);
        if(extensionTuples == null)
        {
            return;
        }

        for(ASN1ObjectIdentifier extType : extensionTuples.getExtensionTypes())
        {
            ExtensionValue extValue = extensionTuples.getExtensionValue(extType);
            certBuilder.addExtension(extType, extValue.isCritical(), extValue.getValue());
        }
    }

    public static AsymmetricKeyParameter generatePublicKeyParameter(
            final PublicKey key)
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
