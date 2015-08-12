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

package org.xipki.security;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.InvalidConfException;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.password.api.PasswordResolver;
import org.xipki.password.api.PasswordResolverException;
import org.xipki.security.api.AbstractSecurityFactory;
import org.xipki.security.api.CmpUtf8Pairs;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.KeyCertPair;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.SignatureAlgoControl;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11Control;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11CryptServiceFactory;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11ModuleConf;
import org.xipki.security.api.p11.P11NullPasswordRetriever;
import org.xipki.security.api.p11.P11PasswordRetriever;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.api.util.AlgorithmUtil;
import org.xipki.security.api.util.X509Util;
import org.xipki.security.p11.P11ContentSignerBuilder;
import org.xipki.security.p11.P11PasswordRetrieverImpl;
import org.xipki.security.p11.conf.jaxb.ModuleType;
import org.xipki.security.p11.conf.jaxb.ModulesType;
import org.xipki.security.p11.conf.jaxb.NativeLibraryType;
import org.xipki.security.p11.conf.jaxb.ObjectFactory;
import org.xipki.security.p11.conf.jaxb.PKCS11ConfType;
import org.xipki.security.p11.conf.jaxb.PasswordType;
import org.xipki.security.p11.conf.jaxb.PasswordsType;
import org.xipki.security.p11.conf.jaxb.SlotType;
import org.xipki.security.p11.conf.jaxb.SlotsType;
import org.xipki.security.p11.iaik.IaikP11CryptServiceFactory;
import org.xipki.security.p11.keystore.KeystoreP11CryptServiceFactory;
import org.xipki.security.p11.remote.RemoteP11CryptServiceFactory;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public class SecurityFactoryImpl extends AbstractSecurityFactory
{
    private static final Logger LOG = LoggerFactory.getLogger(SecurityFactoryImpl.class);

    private String pkcs11Provider;
    private int defaultParallelism = 20;

    private P11Control p11Control;

    private P11CryptServiceFactory p11CryptServiceFactory;
    private boolean p11CryptServiciceFactoryInitialized;

    private PasswordResolver passwordResolver;
    private String pkcs11ConfFile;
    private final Map<String, String> signerTypeMapping = new HashMap<>();

    public SecurityFactoryImpl()
    {
        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public ConcurrentContentSigner createSigner(
            final String type,
            final String confWithoutAlgo,
            final String hashAlgo,
            final SignatureAlgoControl sigAlgoControl,
            final X509Certificate[] certs)
    throws SignerException
    {
        ConcurrentContentSigner signer = doCreateSigner(type, confWithoutAlgo, hashAlgo, sigAlgoControl, certs);
        validateSigner(signer, certs, type, confWithoutAlgo);
        return signer;
    }

    @Override
    public ConcurrentContentSigner createSigner(
            final String type,
            final String conf,
            final X509Certificate[] certificateChain)
    throws SignerException
    {
        ConcurrentContentSigner signer = doCreateSigner(type, conf, null, null, certificateChain);
        validateSigner(signer, certificateChain, type, conf);
        return signer;
    }

    private static void validateSigner(
            final ConcurrentContentSigner signer,
            final X509Certificate[] certificateChain,
            final String signerType,
            final String signerConf)
    throws SignerException
    {
        X509Certificate cert = signer.getCertificate();
        if(certificateChain == null)
        {
            return;
        }

        String signatureAlgoName;
        try
        {
            signatureAlgoName = AlgorithmUtil.getSignatureAlgoName(signer.getAlgorithmIdentifier());
        } catch (NoSuchAlgorithmException e)
        {
            throw new SignerException(e.getMessage(), e);
        }

        ContentSigner csigner;
        try
        {
            csigner = signer.borrowContentSigner();
        } catch (NoIdleSignerException e)
        {
            throw new SignerException(e.getMessage(), e);
        }

        try
        {
            byte[] dummyContent = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
            Signature verifier = Signature.getInstance(signatureAlgoName, "BC");

            OutputStream signatureStream = csigner.getOutputStream();
            signatureStream.write(dummyContent);
            byte[] signatureValue = csigner.getSignature();

            verifier.initVerify(cert.getPublicKey());
            verifier.update(dummyContent);
            boolean valid = verifier.verify(signatureValue);
            if(valid == false)
            {
                String subject = X509Util.getRFC4519Name(cert.getSubjectX500Principal());

                StringBuilder sb = new StringBuilder();
                sb.append("key and certificate not match. ");
                sb.append("key type='").append(signerType).append("'; ");

                CmpUtf8Pairs keyValues = new CmpUtf8Pairs(signerConf);
                String pwd = keyValues.getValue("password");
                if(pwd != null)
                {
                    keyValues.putUtf8Pair("password", "****");
                }
                keyValues.putUtf8Pair("algo", signatureAlgoName);
                sb.append("conf='").append(keyValues.getEncoded()).append("', ");
                sb.append("certificate subject='").append(subject).append("'");

                throw new SignerException(sb.toString());
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException |
                SignatureException | NoSuchProviderException e)
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
    }

    /*
     * sigAlgoControl will be considered only if hashAlgo is not set
     *
     */
    private ConcurrentContentSigner doCreateSigner(
            String type,
            final String conf,
            final String hashAlgo,
            final SignatureAlgoControl sigAlgoControl,
            final X509Certificate[] certificateChain)
    throws SignerException
    {
        if(signerTypeMapping.containsKey(type))
        {
            type = signerTypeMapping.get(type);
        }

        if("PKCS11".equalsIgnoreCase(type) || "PKCS12".equalsIgnoreCase(type) || "JKS".equalsIgnoreCase(type))
        {
            CmpUtf8Pairs keyValues = new CmpUtf8Pairs(conf);

            String s = keyValues.getValue("parallelism");
            int parallelism = defaultParallelism;
            if(s != null)
            {
                try
                {
                    parallelism = Integer.parseInt(s);
                }catch(NumberFormatException e)
                {
                    throw new SignerException("invalid parallelism " + s);
                }

                if(parallelism < 1)
                {
                    throw new SignerException("invalid parallelism " + s);
                }
            }

            if("PKCS11".equalsIgnoreCase(type))
            {
                String pkcs11Module = keyValues.getValue("module");
                if(pkcs11Module == null)
                {
                    pkcs11Module = DEFAULT_P11MODULE_NAME;
                }

                s = keyValues.getValue("slot");
                Integer slotIndex = (s == null) ? null : Integer.parseInt(s);

                s = keyValues.getValue("slot-id");
                Long slotId = (s == null) ? null : Long.parseLong(s);

                if((slotIndex == null && slotId == null) || (slotIndex != null && slotId != null))
                {
                    throw new SignerException("exactly one of slot (index) and slot-id must be specified");
                }
                P11SlotIdentifier slot = new P11SlotIdentifier(slotIndex, slotId);

                String keyLabel = keyValues.getValue("key-label");
                s = keyValues.getValue("key-id");
                byte[] keyId = null;
                if(s != null)
                {
                    keyId = Hex.decode(s);
                }

                if((keyId == null && keyLabel == null) || (keyId != null && keyLabel != null))
                {
                    throw new SignerException("exactly one of key-id and key-label must be specified");
                }

                P11KeyIdentifier keyIdentifier;
                if(keyId != null)
                {
                    keyIdentifier = new P11KeyIdentifier(keyId);
                }
                else
                {
                    keyIdentifier = new P11KeyIdentifier(keyLabel);
                }

                P11CryptService p11CryptService = getP11CryptService(pkcs11Module);
                P11ContentSignerBuilder signerBuilder = new P11ContentSignerBuilder(
                            p11CryptService, slot, keyIdentifier, certificateChain);

                try
                {
                    AlgorithmIdentifier signatureAlgId;
                    if(hashAlgo == null)
                    {
                        signatureAlgId = getSignatureAlgoId(conf);
                    }
                    else
                    {
                        PublicKey pubKey;
                        try
                        {
                            pubKey = getPkcs11PublicKey(pkcs11Module, slot, keyIdentifier);
                        } catch (InvalidKeyException e)
                        {
                            throw new SignerException("invalid key: " + e.getMessage(), e);
                        }

                        signatureAlgId = AlgorithmUtil.getSignatureAlgoId(pubKey, hashAlgo, sigAlgoControl);
                    }
                    return signerBuilder.createSigner(signatureAlgId, parallelism);
                } catch (OperatorCreationException | NoSuchPaddingException | NoSuchAlgorithmException e)
                {
                    throw new SignerException(e.getMessage(), e);
                }

            }
            else
            {
                String passwordHint = keyValues.getValue("password");
                char[] password;
                if(passwordHint == null)
                {
                    password = null;
                }
                else
                {
                    if(passwordResolver == null)
                    {
                        password = passwordHint.toCharArray();
                    }
                    else
                    {
                        try
                        {
                            password = passwordResolver.resolvePassword(passwordHint);
                        }catch(PasswordResolverException e)
                        {
                            throw new SignerException("could not resolve password. Message: " + e.getMessage());
                        }
                    }
                }

                s = keyValues.getValue("keystore");
                String keyLabel = keyValues.getValue("key-label");

                InputStream keystoreStream;
                if(StringUtil.startsWithIgnoreCase(s, "base64:"))
                {
                    keystoreStream = new ByteArrayInputStream(
                            Base64.decode(s.substring("base64:".length())));
                }
                else if(StringUtil.startsWithIgnoreCase(s, "file:"))
                {
                    String fn = s.substring("file:".length());
                    try
                    {
                        keystoreStream = new FileInputStream(IoUtil.expandFilepath(fn));
                    } catch (FileNotFoundException e)
                    {
                        throw new SignerException("file not found: " + fn);
                    }
                }
                else
                {
                    throw new SignerException("unknown keystore content format");
                }

                SoftTokenContentSignerBuilder signerBuilder = new SoftTokenContentSignerBuilder(
                        type, keystoreStream, password, keyLabel, password, certificateChain);

                try
                {
                    AlgorithmIdentifier signatureAlgId;
                    if(hashAlgo == null)
                    {
                        signatureAlgId = getSignatureAlgoId(conf);
                    }
                    else
                    {
                        PublicKey pubKey = signerBuilder.getCert().getPublicKey();
                        signatureAlgId = AlgorithmUtil.getSignatureAlgoId(
                                pubKey, hashAlgo, sigAlgoControl);
                    }

                    return signerBuilder.createSigner(
                            signatureAlgId, parallelism);
                } catch (OperatorCreationException | NoSuchPaddingException | NoSuchAlgorithmException e)
                {
                    throw new SignerException(e.getMessage());
                }
            }
        }
        else if(StringUtil.startsWithIgnoreCase(type, "java:"))
        {
            if(hashAlgo == null)
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
        else
        {
            throw new SignerException("unknwon type: " + type);
        }
    }

    private AlgorithmIdentifier getSignatureAlgoId(
            final String signerConf)
    throws SignerException
    {
        CmpUtf8Pairs keyValues = new CmpUtf8Pairs(signerConf);
        String algoS = keyValues.getValue("algo");
        if(algoS == null)
        {
            throw new SignerException("algo is not specified");
        }
        try
        {
            return AlgorithmUtil.getSignatureAlgoId(algoS);
        } catch (NoSuchAlgorithmException e)
        {
            throw new SignerException(e.getMessage(), e);
        }
    }

    @Override
    public ContentVerifierProvider getContentVerifierProvider(
            final PublicKey publicKey)
    throws InvalidKeyException
    {
        try
        {
            return KeyUtil.getContentVerifierProvider(publicKey);
        } catch (OperatorCreationException e)
        {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    @Override
    public PublicKey generatePublicKey(
            final SubjectPublicKeyInfo subjectPublicKeyInfo)
    throws InvalidKeyException
    {
        try
        {
            return KeyUtil.generatePublicKey(subjectPublicKeyInfo);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    @Override
    public boolean verifyPOPO(
            final CertificationRequest p10Req)
    {
        return SignerUtil.verifyPOP(p10Req);
    }

    public void setPkcs11Provider(
            final String pkcs11Provider)
    {
        this.pkcs11Provider = pkcs11Provider;
    }

    @Override
    public String getPkcs11Provider()
    {
        return pkcs11Provider;
    }

    public void setDefaultParallelism(
            final int defaultParallelism)
    {
        if(defaultParallelism > 0)
        {
            this.defaultParallelism = defaultParallelism;
        }
    }

    public static String getKeystoreSignerConf(
            final String keystoreFile,
            final String password,
            final String signatureAlgorithm,
            final int parallelism)
    {
        return getKeystoreSignerConf(keystoreFile, password, signatureAlgorithm, parallelism, null);
    }

    public static String getKeystoreSignerConf(
            final String keystoreFile,
            final String password,
            final String signatureAlgorithm,
            final int parallelism,
            final String keyLabel)
    {
        ParamUtil.assertNotBlank("keystoreFile", keystoreFile);
        ParamUtil.assertNotBlank("password", password);
        ParamUtil.assertNotNull("signatureAlgorithm", signatureAlgorithm);

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

    public static String getKeystoreSignerConfWithoutAlgo(
            final String keystoreFile,
            final String password,
            final int parallelism)
    {
        return getKeystoreSignerConfWithoutAlgo(keystoreFile, password, parallelism, null);
    }

    public static String getKeystoreSignerConfWithoutAlgo(
            final String keystoreFile,
            final String password,
            final int parallelism,
            final String keyLabel)
    {
        ParamUtil.assertNotBlank("keystoreFile", keystoreFile);
        ParamUtil.assertNotBlank("password", password);

        CmpUtf8Pairs conf = new CmpUtf8Pairs("password", password);
        conf.putUtf8Pair("parallelism", Integer.toString(parallelism));
        if(keyLabel != null)
        {
            conf.putUtf8Pair("key-label", keyLabel);
        }
        conf.putUtf8Pair("keystore", "file:" + keystoreFile);

        return conf.getEncoded();
    }

    public static String getPkcs11SignerConf(
            final String pkcs11ModuleName,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId,
            final String signatureAlgorithm,
            final int parallelism)
    {
        ParamUtil.assertNotNull("algo", signatureAlgorithm);
        ParamUtil.assertNotNull("keyId", keyId);

        CmpUtf8Pairs conf = new CmpUtf8Pairs("algo", signatureAlgorithm);
        conf.putUtf8Pair("parallelism", Integer.toString(parallelism));

        if(pkcs11ModuleName != null && pkcs11ModuleName.length() > 0)
        {
            conf.putUtf8Pair("module", pkcs11ModuleName);
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

    public static String getPkcs11SignerConfWithoutAlgo(
            final String pkcs11ModuleName,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId,
            final int parallelism)
    {
        ParamUtil.assertNotNull("keyId", keyId);

        CmpUtf8Pairs conf = new CmpUtf8Pairs();
        conf.putUtf8Pair("parallelism", Integer.toString(parallelism));

        if(pkcs11ModuleName != null && pkcs11ModuleName.length() > 0)
        {
            conf.putUtf8Pair("module", pkcs11ModuleName);
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
    public P11CryptService getP11CryptService(
            final String moduleName)
    throws SignerException
    {
        initP11CryptServiceFactory();
        return p11CryptServiceFactory.createP11CryptService(
                getRealPkcs11ModuleName(moduleName));
    }

    @Override
    public Set<String> getPkcs11ModuleNames()
    {
        initPkcs11ModuleConf();
        return p11Control == null ? null : p11Control.getModuleNames();
    }

    private synchronized void initP11CryptServiceFactory()
    throws SignerException
    {
        if(p11CryptServiceFactory != null)
        {
            return;
        }

        if(p11CryptServiciceFactoryInitialized)
        {
            throw new SignerException("initialization of P11CryptServiceFactory has been processed and failed, no retry");
        }

        try
        {
            initPkcs11ModuleConf();

            Object p11Provider;

            if(IaikP11CryptServiceFactory.class.getName().equals(pkcs11Provider))
            {
                p11Provider = new IaikP11CryptServiceFactory();
            }
            else if(KeystoreP11CryptServiceFactory.class.getName().equals(pkcs11Provider))
            {
                p11Provider = new KeystoreP11CryptServiceFactory();
            }
            else if(RemoteP11CryptServiceFactory.class.getName().equals(pkcs11Provider))
            {
                p11Provider = new RemoteP11CryptServiceFactory();
            }
            else
            {
                try
                {
                    Class<?> clazz = Class.forName(pkcs11Provider);
                    p11Provider = clazz.newInstance();
                }catch(Exception e)
                {
                    throw new SignerException(e.getMessage(), e);
                }
            }

            if(p11Provider instanceof P11CryptServiceFactory)
            {
                P11CryptServiceFactory p11CryptServiceFact = (P11CryptServiceFactory) p11Provider;
                p11CryptServiceFact.init(p11Control);
                this.p11CryptServiceFactory = p11CryptServiceFact;
            }
            else
            {
                throw new SignerException(pkcs11Provider + " is not instanceof " + P11CryptServiceFactory.class.getName());
            }
        }finally
        {
            p11CryptServiciceFactoryInitialized = true;
        }
    }

    private void initPkcs11ModuleConf()
    {
        if(p11Control != null)
        {
            return;
        }

        if(StringUtil.isBlank(pkcs11ConfFile))
        {
            throw new IllegalStateException("pkcs11ConfFile is not set");
        }

        try
        {
            JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            SchemaFactory schemaFact = SchemaFactory.newInstance(javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = schemaFact.newSchema(getClass().getResource("/xsd/pkcs11-conf.xsd"));
            unmarshaller.setSchema(schema);
            @SuppressWarnings("unchecked")
            JAXBElement<PKCS11ConfType> rootElement = (JAXBElement<PKCS11ConfType>)
                    unmarshaller.unmarshal(new File(pkcs11ConfFile));
            PKCS11ConfType pkcs11Conf = rootElement.getValue();
            ModulesType modulesType = pkcs11Conf.getModules();

            Map<String, P11ModuleConf> confs = new HashMap<>();
            for(ModuleType moduleType : modulesType.getModule())
            {
                String name = moduleType.getName();
                if(DEFAULT_P11MODULE_NAME.equals(name))
                {
                    throw new InvalidConfException("invald module name " + DEFAULT_P11MODULE_NAME + ", it is reserved");
                }

                if(confs.containsKey(name))
                {
                    throw new InvalidConfException("multiple modules with the same module name is not permitted");
                }

                P11PasswordRetriever pwdRetriever;

                PasswordsType passwordsType = moduleType.getPasswords();
                if(passwordsType == null || CollectionUtil.isEmpty(passwordsType.getPassword()))
                {
                    pwdRetriever = P11NullPasswordRetriever.INSTANCE;
                }
                else
                {
                    pwdRetriever = new P11PasswordRetrieverImpl();
                    ((P11PasswordRetrieverImpl) pwdRetriever).setPasswordResolver(passwordResolver);

                    for(PasswordType passwordType : passwordsType.getPassword())
                    {
                        Set<P11SlotIdentifier> slots = getSlots(passwordType.getSlots());
                        ((P11PasswordRetrieverImpl) pwdRetriever).addPasswordEntry(
                                slots, new ArrayList<>(passwordType.getSinglePassword()));
                    }
                }

                Set<P11SlotIdentifier> includeSlots = getSlots(moduleType.getIncludeSlots());
                Set<P11SlotIdentifier> excludeSlots = getSlots(moduleType.getExcludeSlots());

                final String osName = System.getProperty("os.name").toLowerCase();
                String nativeLibraryPath = null;
                for(NativeLibraryType library : moduleType.getNativeLibraries().getNativeLibrary())
                {
                    List<String> osNames = library.getOs();
                    if(CollectionUtil.isEmpty(osNames))
                    {
                        nativeLibraryPath = library.getPath();
                    }
                    else
                    {
                        for(String entry : osNames)
                        {
                            if(osName.contains(entry.toLowerCase()))
                            {
                                nativeLibraryPath = library.getPath();
                                break;
                            }
                        }
                    }

                    if(nativeLibraryPath != null)
                    {
                        break;
                    }
                }

                if(nativeLibraryPath == null)
                {
                    throw new InvalidConfException("could not find PKCS#11 library for OS " + osName);
                }

                P11ModuleConf conf = new P11ModuleConf(name,
                        nativeLibraryPath, pwdRetriever, includeSlots, excludeSlots);
                confs.put(name, conf);
            }

            final String defaultModuleName = modulesType.getDefaultModule();
            if(confs.containsKey(defaultModuleName) == false)
            {
                throw new InvalidConfException("default module " + defaultModuleName + " is not defined");
            }

            this.p11Control = new P11Control(defaultModuleName, new HashSet<>(confs.values()));
        } catch (JAXBException | SAXException | InvalidConfException e)
        {
            final String message = "invalid configuration file " + pkcs11ConfFile;
            if(LOG.isErrorEnabled())
            {
                final String exceptionMessage;
                if(e instanceof JAXBException)
                {
                    exceptionMessage = getMessage((JAXBException) e);
                } else
                {
                    exceptionMessage = e.getMessage();
                }
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), exceptionMessage);
            }
            LOG.debug(message, e);

            throw new RuntimeException(message);
        }
    }

    public void setPkcs11ConfFile(
            final String confFile)
    {
        if(StringUtil.isBlank(confFile))
        {
            this.pkcs11ConfFile = null;
        }
        else
        {
            this.pkcs11ConfFile = confFile;
        }
    }

    private static Set<P11SlotIdentifier> getSlots(
            final SlotsType type)
    throws InvalidConfException
    {
        if(type == null || CollectionUtil.isEmpty(type.getSlot()))
        {
            return null;
        }

        Set<P11SlotIdentifier> slots = new HashSet<>();
        for(SlotType slotType : type.getSlot())
        {
            Long slotId = null;
            if(slotType.getId() != null)
            {
                String str = slotType.getId().trim();
                try
                {
                    if(StringUtil.startsWithIgnoreCase(str, "0X"))
                    {
                        slotId = Long.parseLong(str.substring(2), 16);
                    }
                    else
                    {
                        slotId = Long.parseLong(str);
                    }
                }catch(NumberFormatException e)
                {
                    String message = "invalid slotId '" + str + "'";
                    LOG.error(message);
                    throw new InvalidConfException(message);
                }
            }
            slots.add(new P11SlotIdentifier(slotType.getIndex(), slotId));
        }

        return slots;
    }

    private String getRealPkcs11ModuleName(
            final String moduleName)
    {
        if(moduleName == null || DEFAULT_P11MODULE_NAME.equals(moduleName))
        {
            return getDefaultPkcs11ModuleName();
        }
        else
        {
            return moduleName;
        }
    }

    public void setPasswordResolver(
            final PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }

    @Override
    public String getDefaultPkcs11ModuleName()
    {
        initPkcs11ModuleConf();
        return p11Control == null ? null : p11Control.getDefaultModuleName();
    }

    @Override
    public PasswordResolver getPasswordResolver()
    {
        return passwordResolver;
    }

    @Override
    public PublicKey getPkcs11PublicKey(
            final String moduleName,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws InvalidKeyException
    {
        try
        {
            P11CryptService p11 = getP11CryptService(moduleName);
            return p11 == null ? null : p11.getPublicKey(slotId, keyId);
        } catch (SignerException e)
        {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    public void setSignerTypeMap(
            String signerTypeMap)
    {
        if(signerTypeMap == null)
        {
            LOG.debug("signerTypeMap is null");
            return;
        }

        signerTypeMap = signerTypeMap.trim();
        if(StringUtil.isBlank(signerTypeMap))
        {
            LOG.debug("signerTypeMap is empty");
            return;
        }

        StringTokenizer st = new StringTokenizer(signerTypeMap, " \t");
        while(st.hasMoreTokens())
        {
            String token = st.nextToken();
            StringTokenizer st2 = new StringTokenizer(token, "=");
            if(st2.countTokens() != 2)
            {
                LOG.warn("invalid signerTypeMap entry '" + token + "'");
                continue;
            }

            String alias = st2.nextToken();
            if(signerTypeMapping.containsKey(alias))
            {
                LOG.warn("signerType alias '" + alias + "' already defined, ignore map '" + token +"'");
                continue;
            }
            String signerType = st2.nextToken();
            signerTypeMapping.put(alias, signerType);
            LOG.info("add alias '" + alias + "' for signerType '" + signerType + "'");
        }
    }

    @Override
    public KeyCertPair createPrivateKeyAndCert(
            final String type,
            final String conf,
            final X509Certificate cert)
    throws SignerException
    {
        if("PKCS11".equalsIgnoreCase(type) == false && "PKCS12".equalsIgnoreCase(type) == false)
        {
            throw new SignerException("unsupported SCEP responder type '" + type + "'");
        }

        CmpUtf8Pairs keyValues = new CmpUtf8Pairs(conf);

        String passwordHint = keyValues.getValue("password");
        char[] password;
        if(passwordHint == null)
        {
            password = null;
        }
        else
        {
            if(passwordResolver == null)
            {
                password = passwordHint.toCharArray();
            }
            else
            {
                try
                {
                    password = passwordResolver.resolvePassword(passwordHint);
                }catch(PasswordResolverException e)
                {
                    throw new SignerException("could not resolve password. Message: " + e.getMessage());
                }
            }
        }

        String s = keyValues.getValue("keystore");
        String keyLabel = keyValues.getValue("key-label");

        InputStream keystoreStream;
        if(StringUtil.startsWithIgnoreCase(s, "base64:"))
        {
            keystoreStream = new ByteArrayInputStream(
                    Base64.decode(s.substring("base64:".length())));
        }
        else if(StringUtil.startsWithIgnoreCase(s, "file:"))
        {
            String fn = s.substring("file:".length());
            try
            {
                keystoreStream = new FileInputStream(IoUtil.expandFilepath(fn));
            } catch (FileNotFoundException e)
            {
                throw new SignerException("file not found: " + fn);
            }
        }
        else
        {
            throw new SignerException("unknown keystore content format");
        }

        SoftTokenContentSignerBuilder signerBuilder = new SoftTokenContentSignerBuilder(
                type, keystoreStream, password, keyLabel, password,
                cert == null ? null : new X509Certificate[]{cert});

        KeyCertPair keycertPair = new KeyCertPair(
                signerBuilder.getKey(), signerBuilder.getCert());
        // TODO: validiate whether private key and certificate match
        return keycertPair;
    }

    private static String getMessage(
            final JAXBException e)
    {
        String ret = e.getMessage();
        if(ret == null && e.getLinkedException() != null)
        {
            ret = e.getLinkedException().getMessage();
        }
        return ret;
    }

}
