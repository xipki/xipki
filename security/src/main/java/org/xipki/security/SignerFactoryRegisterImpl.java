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

package org.xipki.security;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.ConcurrentLinkedDeque;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.ObjectCreationException;
import org.xipki.common.util.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.P11ContentSignerBuilder;
import org.xipki.security.pkcs11.P11CryptService;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11EntityIdentifier;
import org.xipki.security.pkcs11.P11MacContentSignerBuilder;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.security.pkcs12.SoftTokenContentSignerBuilder;
import org.xipki.security.pkcs12.SoftTokenMacContentSignerBuilder;
import org.xipki.security.util.AlgorithmUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignerFactoryRegisterImpl implements SignerFactoryRegister {

    private static final Logger LOG = LoggerFactory.getLogger(SignerFactoryRegisterImpl.class);

    private P11CryptServiceFactory p11CryptServiceFactory;

    private ConcurrentLinkedDeque<SignerFactory> services =
            new ConcurrentLinkedDeque<SignerFactory>();

    public void setP11CryptServiceFactory(final P11CryptServiceFactory p11CryptServiceFactory) {
        this.p11CryptServiceFactory = p11CryptServiceFactory;
    }

    public void bindService(final SignerFactory service) {
        //might be null if dependency is optional
        if (service == null) {
            LOG.info("bindService invoked with null.");
            return;
        }

        boolean replaced = services.remove(service);
        services.add(service);

        String action = replaced ? "replaced" : "added";
        LOG.info("{} SignerFactory binding for {}", action, service);
    }

    public void unbindService(final SignerFactory service) {
        //might be null if dependency is optional
        if (service == null) {
            LOG.info("unbindService invoked with null.");
            return;
        }

        if (services.remove(service)) {
            LOG.info("removed SignerFactory binding for {}", service);
        } else {
            LOG.info("no SignerFactory binding found to remove for '{}'", service);
        }
    }

    @Override
    public ConcurrentContentSigner newSigner(final SecurityFactory securityFactory,
            final String type, final SignerConf conf, final X509Certificate[] certificateChain)
            throws ObjectCreationException {
        ParamUtil.requireNonBlank("type", type);

        if ("PKCS12".equalsIgnoreCase(type)
                || "JKS".equalsIgnoreCase(type)
                || "JCEKS".equalsIgnoreCase(type)) {
            return newKeystoreSigner(securityFactory, type, conf, certificateChain);
        }

        if ("PKCS11".equalsIgnoreCase(type)) {
            return newPkcs11Signer(securityFactory, type, conf, certificateChain);
        }

        for (SignerFactory service : services) {
            if (service.canCreateSigner(type)) {
                return service.newSigner(type, conf, certificateChain);
            }
        }

        throw new ObjectCreationException(
                "could not find Factory to create Signer of type '" + type + "'");
    }

    private ConcurrentContentSigner newKeystoreSigner(final SecurityFactory securityFactory,
            final String type, final SignerConf conf, final X509Certificate[] certificateChain)
            throws ObjectCreationException {
        String str = conf.getConfValue("parallelism");
        int parallelism = securityFactory.getDefaultSignerParallelism();
        if (str != null) {
            try {
                parallelism = Integer.parseInt(str);
            } catch (NumberFormatException ex) {
                throw new ObjectCreationException("invalid parallelism " + str);
            }

            if (parallelism < 1) {
                throw new ObjectCreationException("invalid parallelism " + str);
            }
        }

        String passwordHint = conf.getConfValue("password");
        char[] password;
        if (passwordHint == null) {
            password = null;
        } else {
            PasswordResolver passwordResolver = securityFactory.getPasswordResolver();
            if (passwordResolver == null) {
                password = passwordHint.toCharArray();
            } else {
                try {
                    password = passwordResolver.resolvePassword(passwordHint);
                } catch (PasswordResolverException ex) {
                    throw new ObjectCreationException(
                            "could not resolve password. Message: " + ex.getMessage());
                }
            }
        }

        str = conf.getConfValue("keystore");
        String keyLabel = conf.getConfValue("key-label");

        InputStream keystoreStream;
        if (StringUtil.startsWithIgnoreCase(str, "base64:")) {
            keystoreStream = new ByteArrayInputStream(
                    Base64.decode(str.substring("base64:".length())));
        } else if (StringUtil.startsWithIgnoreCase(str, "file:")) {
            String fn = str.substring("file:".length());
            try {
                keystoreStream = new FileInputStream(IoUtil.expandFilepath(fn));
            } catch (FileNotFoundException ex) {
                throw new ObjectCreationException("file not found: " + fn);
            }
        } else {
            throw new ObjectCreationException("unknown keystore content format");
        }

        try {
            AlgorithmIdentifier macAlgId = null;
            String algoName = conf.getConfValue("algo");
            if (algoName != null) {
                try {
                    macAlgId = AlgorithmUtil.getMacAlgId(algoName);
                } catch (NoSuchAlgorithmException ex) {
                    // do nothing
                }
            }

            if (macAlgId != null) {
                SoftTokenMacContentSignerBuilder signerBuilder =
                        new SoftTokenMacContentSignerBuilder(
                                type, keystoreStream, password, keyLabel, password);

                return signerBuilder.createSigner(macAlgId, parallelism,
                        securityFactory.getRandom4Sign());
            } else {
                SoftTokenContentSignerBuilder signerBuilder = new SoftTokenContentSignerBuilder(
                        type, keystoreStream, password, keyLabel, password, certificateChain);

                AlgorithmIdentifier signatureAlgId;
                if (conf.hashAlgo() == null) {
                    signatureAlgId = AlgorithmUtil.getSigAlgId(null, conf);
                } else {
                    PublicKey pubKey = signerBuilder.certificate().getPublicKey();
                    signatureAlgId = AlgorithmUtil.getSigAlgId(pubKey, conf);
                }

                return signerBuilder.createSigner(signatureAlgId, parallelism,
                        securityFactory.getRandom4Sign());
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | XiSecurityException ex) {
            throw new ObjectCreationException(String.format("%s: %s", ex.getClass().getName(),
                    ex.getMessage()));
        }
    }

    public ConcurrentContentSigner newPkcs11Signer(final SecurityFactory securityFactory,
            final String type, final SignerConf conf, final X509Certificate[] certificateChain)
            throws ObjectCreationException {
        if (p11CryptServiceFactory == null) {
            throw new ObjectCreationException("p11CryptServiceFactory is not set");
        }

        String str = conf.getConfValue("parallelism");
        int parallelism = securityFactory.getDefaultSignerParallelism();
        if (str != null) {
            try {
                parallelism = Integer.parseInt(str);
            } catch (NumberFormatException ex) {
                throw new ObjectCreationException("invalid parallelism " + str);
            }

            if (parallelism < 1) {
                throw new ObjectCreationException("invalid parallelism " + str);
            }
        }

        String moduleName = conf.getConfValue("module");
        str = conf.getConfValue("slot");
        Integer slotIndex = (str == null) ? null : Integer.parseInt(str);

        str = conf.getConfValue("slot-id");
        Long slotId = (str == null) ? null : Long.parseLong(str);

        if ((slotIndex == null && slotId == null)
                || (slotIndex != null && slotId != null)) {
            throw new ObjectCreationException(
                    "exactly one of slot (index) and slot-id must be specified");
        }

        String keyLabel = conf.getConfValue("key-label");
        str = conf.getConfValue("key-id");
        byte[] keyId = null;
        if (str != null) {
            keyId = Hex.decode(str);
        }

        if ((keyId == null && keyLabel == null)
                || (keyId != null && keyLabel != null)) {
            throw new ObjectCreationException(
                    "exactly one of key-id and key-label must be specified");
        }

        P11CryptService p11Service;
        P11Slot slot;
        try {
            p11Service = p11CryptServiceFactory.getP11CryptService(moduleName);
            P11Module module = p11Service.module();
            P11SlotIdentifier p11SlotId;
            if (slotId != null) {
                p11SlotId = module.getSlotIdForId(slotId);
            } else if (slotIndex != null) {
                p11SlotId = module.getSlotIdForIndex(slotIndex);
            } else {
                throw new RuntimeException("should not reach here");
            }
            slot = module.getSlot(p11SlotId);
        } catch (P11TokenException | XiSecurityException ex) {
            throw new ObjectCreationException(ex.getMessage(), ex);
        }

        P11ObjectIdentifier p11ObjId = (keyId != null)
                ? slot.getObjectIdForId(keyId)
                : slot.getObjectIdForLabel(keyLabel);
        if (p11ObjId == null) {
            String str2 = (keyId != null) ? "id " + Hex.toHexString(keyId) : "label " + keyLabel;
            throw new ObjectCreationException("cound not find identity with " + str2);
        }
        P11EntityIdentifier entityId = new P11EntityIdentifier(slot.slotId(), p11ObjId);

        try {
            AlgorithmIdentifier macAlgId = null;
            String algoName = conf.getConfValue("algo");
            if (algoName != null) {
                try {
                    macAlgId = AlgorithmUtil.getMacAlgId(algoName);
                } catch (NoSuchAlgorithmException ex) {
                    // do nothing
                }
            }

            if (macAlgId != null) {
                P11MacContentSignerBuilder signerBuilder = new P11MacContentSignerBuilder(
                        p11Service, entityId);
                return signerBuilder.createSigner(macAlgId, parallelism);
            } else {
                AlgorithmIdentifier signatureAlgId;
                if (conf.hashAlgo() == null) {
                    signatureAlgId = AlgorithmUtil.getSigAlgId(null, conf);
                } else {
                    PublicKey pubKey = slot.getIdentity(p11ObjId).publicKey();
                    signatureAlgId = AlgorithmUtil.getSigAlgId(pubKey, conf);
                }

                P11ContentSignerBuilder signerBuilder = new P11ContentSignerBuilder(p11Service,
                        securityFactory, entityId, certificateChain);
                return signerBuilder.createSigner(signatureAlgId, parallelism);
            }
        } catch (P11TokenException | NoSuchAlgorithmException | XiSecurityException ex) {
            throw new ObjectCreationException(ex.getMessage(), ex);
        }
    }

}
