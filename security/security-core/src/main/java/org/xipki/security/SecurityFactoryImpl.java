/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.StringTokenizer;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.P11CryptService;
import org.xipki.security.api.P11CryptServiceFactory;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;
import org.xipki.security.p11.P11ContentSignerBuilder;

/**
 * @author Lijun Liao
 */

public class SecurityFactoryImpl implements SecurityFactory
{
    private String pkcs11Provider;
    private String pkcs11Module;
    private Set<Integer> pkcs11IncludeSlots;
    private Set<Integer> pkcs11ExcludeSlots;
    private int defaultParallelism = 20;

    public SecurityFactoryImpl()
    {
        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public ConcurrentContentSigner createSigner(
            String type, String conf, X509Certificate cert, PasswordResolver passwordResolver)
    throws SignerException, PasswordResolverException
    {
        return createSigner(type, conf,
                (cert == null ? null : new X509Certificate[]{cert}),
                passwordResolver);
    }

    @Override
    public ConcurrentContentSigner createSigner(
            String type, String conf,
            X509Certificate[] certificateChain,
            PasswordResolver passwordResolver)
    throws SignerException, PasswordResolverException
    {
        ConcurrentContentSigner signer = doCreateSigner(type, conf, certificateChain, passwordResolver);

        X509Certificate cert = signer.getCertificate();
        if(certificateChain == null)
        {
            return signer;
        }

        ContentSigner csigner;
        try
        {
            csigner = signer.borrowContentSigner();
        } catch (NoIdleSignerException e)
        {
            throw new SignerException(e);
        }

        try
        {
            byte[] dummyContent = new byte[]{1,2,3,4,5,6,7,8,9,10};

            CmpUtf8Pairs keyValues = new CmpUtf8Pairs(conf);
            String algoS = keyValues.getValue("algo");
            Signature verifier = Signature.getInstance(algoS, "BC");

            OutputStream signatureStream = csigner.getOutputStream();
            signatureStream.write(dummyContent);
            byte[] signatureValue = csigner.getSignature();

            verifier.initVerify(cert.getPublicKey());
            verifier.update(dummyContent);
            boolean valid = verifier.verify(signatureValue);
            if(valid == false)
            {
                String subject = IoCertUtil.canonicalizeName(cert.getSubjectX500Principal());

                StringBuilder sb = new StringBuilder();
                sb.append("key and certificate not match. ");
                sb.append("key type='").append(type).append("'; ");

                String pwd = keyValues.getValue("password");
                if(pwd != null)
                {
                    keyValues.putUtf8Pair("password", "****");
                }
                sb.append("conf='").append(keyValues.getEncoded()).append("', ");
                sb.append("certificate subject='").append(subject).append("'");

                throw new SignerException(sb.toString());
            }
        } catch (IOException e)
        {
            throw new SignerException(e.getMessage(), e);
        } catch (NoSuchAlgorithmException e)
        {
            throw new SignerException(e.getMessage(), e);
        } catch (InvalidKeyException e)
        {
            throw new SignerException(e.getMessage(), e);
        } catch (SignatureException e)
        {
            throw new SignerException(e.getMessage(), e);
        } catch (NoSuchProviderException e)
        {
            throw new SignerException(e.getMessage(), e);
        }
        finally
        {
            if(csigner != null)
            {
                signer.returnContentSigner(csigner);
            }
        }

        return signer;
    }

    private ConcurrentContentSigner doCreateSigner(
            String type, String conf,
            X509Certificate[] certificateChain,
            PasswordResolver passwordResolver)
    throws SignerException, PasswordResolverException
    {
        if("PKCS11".equalsIgnoreCase(type) || "PKCS12".equalsIgnoreCase(type) || "JKS".equalsIgnoreCase(type))
        {
            CmpUtf8Pairs keyValues = new CmpUtf8Pairs(conf);

            String passwordHint = keyValues.getValue("password");

            String s = keyValues.getValue("parallelism");
            int parallelism = defaultParallelism;
            if(s != null)
            {
                try
                {
                    parallelism = Integer.parseInt(s);
                }catch(NumberFormatException e)
                {
                    throw new SignerException("Invalid parallelism " + s);
                }

                if(parallelism < 1)
                {
                    throw new SignerException("Invalid parallelism " + s);
                }
            }

            String algoS = keyValues.getValue("algo");
            if(algoS == null)
            {
                throw new SignerException("algo is not specified");
            }
            algoS = algoS.replaceAll("-", "");

            AlgorithmIdentifier signatureAlgId;
            if("SHA1withRSA".equalsIgnoreCase(algoS) || "RSAwithSHA1".equalsIgnoreCase(algoS) ||
                    PKCSObjectIdentifiers.sha1WithRSAEncryption.getId().equals(algoS))
            {
                signatureAlgId = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption, DERNull.INSTANCE);
            }
            else if("SHA224withRSA".equalsIgnoreCase(algoS) || "RSAwithSHA224".equalsIgnoreCase(algoS) ||
                    PKCSObjectIdentifiers.sha224WithRSAEncryption.getId().equals(algoS))
            {
                signatureAlgId = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha224WithRSAEncryption, DERNull.INSTANCE);
            }
            else if("SHA256withRSA".equalsIgnoreCase(algoS) || "RSAwithSHA256".equalsIgnoreCase(algoS) ||
                    PKCSObjectIdentifiers.sha256WithRSAEncryption.getId().equals(algoS))
            {
                signatureAlgId = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);
            }
            else if("SHA384withRSA".equalsIgnoreCase(algoS) || "RSAwithSHA384".equalsIgnoreCase(algoS) ||
                    PKCSObjectIdentifiers.sha384WithRSAEncryption.getId().equals(algoS))
            {
                signatureAlgId = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha384WithRSAEncryption, DERNull.INSTANCE);
            }
            else if("SHA512withRSA".equalsIgnoreCase(algoS) || "RSAwithSHA512".equalsIgnoreCase(algoS) ||
                    PKCSObjectIdentifiers.sha512WithRSAEncryption.getId().equals(algoS))
            {
                signatureAlgId = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha512WithRSAEncryption, DERNull.INSTANCE);
            }
            else if("SHA1withECDSA".equalsIgnoreCase(algoS) || "ECDSAwithSHA1".equalsIgnoreCase(algoS) ||
                    X9ObjectIdentifiers.ecdsa_with_SHA1.getId().equals(algoS))
            {
                signatureAlgId = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA1, DERNull.INSTANCE);
            }
            else if("SHA224withECDSA".equalsIgnoreCase(algoS) || "ECDSAwithSHA224".equalsIgnoreCase(algoS) ||
                    X9ObjectIdentifiers.ecdsa_with_SHA224.getId().equals(algoS))
            {
                signatureAlgId = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA224, DERNull.INSTANCE);
            }
            else if("SHA256withECDSA".equalsIgnoreCase(algoS) || "ECDSAwithSHA256".equalsIgnoreCase(algoS) ||
                    X9ObjectIdentifiers.ecdsa_with_SHA256.getId().equals(algoS))
            {
                signatureAlgId = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256, DERNull.INSTANCE);
            }
            else if("SHA384withECDSA".equalsIgnoreCase(algoS) || "ECDSAwithSHA384".equalsIgnoreCase(algoS) ||
                    X9ObjectIdentifiers.ecdsa_with_SHA384.getId().equals(algoS))
            {
                signatureAlgId = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA384, DERNull.INSTANCE);
            }
            else if("SHA512withECDSA".equalsIgnoreCase(algoS) || "ECDSAwithSHA512".equalsIgnoreCase(algoS) ||
                    X9ObjectIdentifiers.ecdsa_with_SHA512.getId().equals(algoS))
            {
                signatureAlgId = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA512, DERNull.INSTANCE);
            }
            else if("SHA1withRSAandMGF1".equalsIgnoreCase(algoS))
            {
                try
                {
                    signatureAlgId = SignerUtil.buildRSAPSSAlgorithmIdentifier(X509ObjectIdentifiers.id_SHA1);
                } catch (NoSuchAlgorithmException e)
                {
                    throw new SignerException(e.getMessage(), e);
                }
            }
            else if("SHA224withRSAandMGF1".equalsIgnoreCase(algoS))
            {
                try
                {
                    signatureAlgId = SignerUtil.buildRSAPSSAlgorithmIdentifier(NISTObjectIdentifiers.id_sha224);
                } catch (NoSuchAlgorithmException e)
                {
                    throw new SignerException(e.getMessage(), e);
                }
            }
            else if("SHA256withRSAandMGF1".equalsIgnoreCase(algoS))
            {
                try
                {
                    signatureAlgId = SignerUtil.buildRSAPSSAlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
                } catch (NoSuchAlgorithmException e)
                {
                    throw new SignerException(e.getMessage(), e);
                }
            }
            else if("SHA384withRSAandMGF1".equalsIgnoreCase(algoS))
            {
                try
                {
                    signatureAlgId = SignerUtil.buildRSAPSSAlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
                } catch (NoSuchAlgorithmException e)
                {
                    throw new SignerException(e.getMessage(), e);
                }
            }
            else if("SHA512withRSAandMGF1".equalsIgnoreCase(algoS))
            {
                try
                {
                    signatureAlgId = SignerUtil.buildRSAPSSAlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
                } catch (NoSuchAlgorithmException e)
                {
                    throw new SignerException(e.getMessage(), e);
                }
            }
            else
            {
                throw new SignerException("Unsupported signature algorithm " + algoS);
            }

            char[] password;
            if(passwordHint == null)
            {
                password = null;
            }
            else
            {
                if(passwordResolver == null)
                {
                    throw new IllegalStateException(
                            "PasswordResolver is not initialized, please call setPasswordResolver first");
                }
                password = passwordResolver.resolvePassword(passwordHint);
            }

            if("PKCS11".equalsIgnoreCase(type))
            {
                String pkcs11Module = keyValues.getValue("module");
                if(pkcs11Module == null)
                {
                    pkcs11Module = this.pkcs11Module;
                }

                s = keyValues.getValue("slot");
                Integer slotIndex = (s == null) ? null : Integer.parseInt(s);

                s = keyValues.getValue("slot-id");
                Long slotId = (s == null) ? null : Long.parseLong(s);

                if((slotIndex == null && slotId == null) || (slotIndex != null && slotId != null))
                {
                    throw new SignerException("Exactly one of slot (index) and slot-id must be specified");
                }
                PKCS11SlotIdentifier slot = new PKCS11SlotIdentifier(slotIndex, slotId);

                String keyLabel = keyValues.getValue("key-label");
                s = keyValues.getValue("key-id");
                byte[] keyId = null;
                if(s != null)
                {
                    keyId = Hex.decode(s);
                }

                if((keyId == null && keyLabel == null) || (keyId != null && keyLabel != null))
                {
                    throw new SignerException("Exactly one of key-id and key-label must be specified");
                }

                Pkcs11KeyIdentifier keyIdentifier;
                if(keyId != null)
                {
                    keyIdentifier = new Pkcs11KeyIdentifier(keyId);
                }
                else
                {
                    keyIdentifier = new Pkcs11KeyIdentifier(keyLabel);
                }

                Object p11Provider;
                try
                {
                    Class<?> clazz = Class.forName(pkcs11Provider);
                    p11Provider = clazz.newInstance();
                }catch(Exception e)
                {
                    throw new SignerException(e.getMessage(), e);
                }

                if(p11Provider instanceof P11CryptServiceFactory)
                {
                    P11CryptServiceFactory p11CryptServiceFact = (P11CryptServiceFactory) p11Provider;
                    P11CryptService p11CryptService = p11CryptServiceFact.createP11CryptService(
                            pkcs11Module, password, pkcs11IncludeSlots, pkcs11ExcludeSlots);
                    P11ContentSignerBuilder signerBuilder = new P11ContentSignerBuilder(
                                p11CryptService, slot, password, keyIdentifier, certificateChain);

                    try
                    {
                        return  signerBuilder.createSigner(signatureAlgId, parallelism);
                    } catch (OperatorCreationException e)
                    {
                        throw new SignerException(e.getMessage());
                    } catch (NoSuchPaddingException e)
                    {
                        throw new SignerException(e.getMessage());
                    }
                }
                {
                    throw new SignerException(pkcs11Module + " is not instanceof " + P11CryptServiceFactory.class.getName());
                }
            }
            else
            {
                s = keyValues.getValue("keystore");
                String keyLabel = keyValues.getValue("key-label");

                InputStream keystoreStream;
                if(s.startsWith("base64:"))
                {
                    keystoreStream = new ByteArrayInputStream(
                            Base64.decode(s.substring("base64:".length())));
                }
                else if(s.startsWith("file:"))
                {
                    String fn = s.substring("file:".length());
                    try
                    {
                        keystoreStream = new FileInputStream(fn);
                    } catch (FileNotFoundException e)
                    {
                        throw new SignerException("File not found: " + fn);
                    }
                }
                else
                {
                    throw new SignerException("Unknown keystore content format");
                }

                SoftTokenContentSignerBuilder signerBuilder;
                try
                {
                    signerBuilder = new SoftTokenContentSignerBuilder(
                            type, keystoreStream, password, keyLabel, password, certificateChain);
                } catch (SignerException e)
                {
                    throw new SignerException(e.getMessage());
                }

                try
                {
                    return signerBuilder.createSigner(
                            signatureAlgId, parallelism);
                } catch (OperatorCreationException e)
                {
                    throw new SignerException(e.getMessage());
                } catch (NoSuchPaddingException e)
                {
                    throw new SignerException(e.getMessage());
                }
            }
        }
        else if(type.toLowerCase().startsWith("java:"))
        {
            ConcurrentContentSigner contentSigner;
            String classname = type.substring("java:".length());
            try
            {
                Class<?> clazz = Class.forName(classname);
                contentSigner = (ConcurrentContentSigner) clazz.newInstance();
            }catch(Exception e)
            {
                throw new SignerException(e.getMessage(), e);
            }
            contentSigner.initialize(conf, passwordResolver);

            if(certificateChain != null)
            {
                contentSigner.setCertificateChain(certificateChain);
            }

            return contentSigner;
        }
        else
        {
            throw new SignerException("unknwon type: " + type);
        }
    }

    @Override
    public ContentVerifierProvider getContentVerifierProvider(
            PublicKey publicKey)
    throws InvalidKeyException
    {
        try
        {
            return KeyUtil.getContentVerifierProvider(publicKey);
        } catch (OperatorCreationException e)
        {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public ContentVerifierProvider getContentVerifierProvider(
            X509Certificate cert)
    throws InvalidKeyException
    {
        try
        {
            return KeyUtil.getContentVerifierProvider(cert);
        } catch (OperatorCreationException e)
        {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public ContentVerifierProvider getContentVerifierProvider(
            X509CertificateHolder cert)
    throws InvalidKeyException
    {
        try
        {
            PublicKey pk = KeyUtil.generatePublicKey(cert.getSubjectPublicKeyInfo());
            return KeyUtil.getContentVerifierProvider(pk);
        } catch (OperatorCreationException e)
        {
            throw new InvalidKeyException(e);
        } catch (NoSuchAlgorithmException e)
        {
            throw new InvalidKeyException(e);
        } catch (InvalidKeySpecException e)
        {
            throw new InvalidKeyException(e);
        } catch (IOException e)
        {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public PublicKey generatePublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
    throws InvalidKeyException
    {
        try
        {
            return KeyUtil.generatePublicKey(subjectPublicKeyInfo);
        } catch (NoSuchAlgorithmException e)
        {
            throw new InvalidKeyException(e);
        } catch (InvalidKeySpecException e)
        {
            throw new InvalidKeyException(e);
        } catch (IOException e)
        {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public boolean verifyPOPO(CertificationRequest p10Req)
    {
        return SignerUtil.verifyPOP(p10Req);
    }

    @Override
    public byte[] generateSelfSignedRSAKeyStore(BigInteger serial,
            String subject, String keystoreType, char[] password,
            String keyLabel, int keysize, BigInteger publicExponent)
    throws SignerException
    {
        return KeyUtil.generateSelfSignedRSAKeyStore(serial, subject, keystoreType,
                password, keyLabel, keysize, publicExponent);
    }

    @Override
    public String getPkcs11Provider()
    {
        return pkcs11Provider;
    }

    public void setPkcs11Provider(String pkcs11Provider)
    {
        this.pkcs11Provider = pkcs11Provider;
    }

    public void setPkcs11IncludeSlots(String indexes)
    {
        this.pkcs11IncludeSlots = getSlotIndexes(indexes);
    }

    public void setPkcs11ExcludeSlots(String indexes)
    {
        this.pkcs11ExcludeSlots = getSlotIndexes(indexes);
    }

    public void setDefaultParallelism(int defaultParallelism)
    {
        if(defaultParallelism > 0)
        {
            this.defaultParallelism = defaultParallelism;
        }
    }

    private static Set<Integer> getSlotIndexes(String indexes)
    {
        if(indexes == null || indexes.trim().isEmpty())
        {
            return null;
        }

        StringTokenizer st = new StringTokenizer(indexes.trim(), ", ");
        if(st.countTokens() == 0)
        {
            return null;
        }

        Set<Integer> slotIndexes = new HashSet<>();
        while(st.hasMoreTokens())
        {
            slotIndexes.add(Integer.parseInt(st.nextToken()));
        }

        return Collections.unmodifiableSet(slotIndexes);
    }

    public static String getKeystoreSignerConf(String keystoreFile, String password,
            String signatureAlgorithm, int parallelism)
    {
        return getKeystoreSignerConf(keystoreFile, password, signatureAlgorithm, parallelism, null);
    }

    public static String getKeystoreSignerConf(String keystoreFile, String password,
            String signatureAlgorithm, int parallelism,
            String keyLabel)
    {
        ParamChecker.assertNotEmpty("keystoreFile", keystoreFile);
        ParamChecker.assertNotEmpty("password", password);
        ParamChecker.assertNotNull("signatureAlgorithm", signatureAlgorithm);

        CmpUtf8Pairs conf = new CmpUtf8Pairs("password", password);
        conf.putUtf8Pair("algo", signatureAlgorithm);
        conf.putUtf8Pair("parallelism", Integer.toString(parallelism));
        if(keyLabel != null)
        {
            conf.putUtf8Pair("key-label", keyLabel);
        }
        conf.putUtf8Pair("keystore", "file:" + keystoreFile);

        return conf.getEncoded();
    }

    public static String getPkcs11SignerConf(String pkcs11Lib, PKCS11SlotIdentifier slotId,
            Pkcs11KeyIdentifier keyId,
            String password,
            String signatureAlgorithm, int parallelism)
    {
        ParamChecker.assertNotNull("algo", signatureAlgorithm);
        ParamChecker.assertNotNull("keyId", keyId);

        CmpUtf8Pairs conf = new CmpUtf8Pairs("algo", signatureAlgorithm);
        conf.putUtf8Pair("parallelism", Integer.toString(parallelism));
        if(password != null && password.length() > 0)
        {
            conf.putUtf8Pair("password", password);
        }

        if(pkcs11Lib != null && pkcs11Lib.length() > 0)
        {
            conf.putUtf8Pair("module", pkcs11Lib);
        }

        if(slotId.getSlotId() != null)
        {
            conf.putUtf8Pair("slot-id", slotId.getSlotId().toString());
        }
        else
        {
            conf.putUtf8Pair("slot", slotId.getSlotIndex().toString());
        }

        if(keyId.getKeyId() != null)
        {
            conf.putUtf8Pair("key-id", Hex.toHexString(keyId.getKeyId()));
        }

        if(keyId.getKeyLabel() != null)
        {
            conf.putUtf8Pair("key-label", keyId.getKeyLabel());
        }

        return conf.getEncoded();
    }

    @Override
    public String getPkcs11Module()
    {
        return pkcs11Module;
    }

    public void setPkcs11Module(String pkcs11Module)
    {
        this.pkcs11Module = pkcs11Module;
    }

    @Override
    public Set<Integer> getPkcs11ExcludeSlotIndexes()
    {
        return pkcs11ExcludeSlots;
    }

    @Override
    public Set<Integer> getPkcs11IncludeSlotIndexes()
    {
        return pkcs11IncludeSlots;
    }

}
