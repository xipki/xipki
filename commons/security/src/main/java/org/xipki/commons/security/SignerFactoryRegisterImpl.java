/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.commons.security;

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
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.ObjectCreationException;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.password.PasswordResolver;
import org.xipki.commons.password.PasswordResolverException;
import org.xipki.commons.security.exception.P11TokenException;
import org.xipki.commons.security.exception.XiSecurityException;
import org.xipki.commons.security.pkcs11.P11ContentSignerBuilder;
import org.xipki.commons.security.pkcs11.P11CryptService;
import org.xipki.commons.security.pkcs11.P11CryptServiceFactory;
import org.xipki.commons.security.pkcs11.P11EntityIdentifier;
import org.xipki.commons.security.pkcs11.P11Module;
import org.xipki.commons.security.pkcs11.P11ObjectIdentifier;
import org.xipki.commons.security.pkcs11.P11Slot;
import org.xipki.commons.security.pkcs11.P11SlotIdentifier;
import org.xipki.commons.security.pkcs12.SoftTokenContentSignerBuilder;
import org.xipki.commons.security.util.AlgorithmUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignerFactoryRegisterImpl implements SignerFactoryRegister {

    private static final Logger LOG = LoggerFactory.getLogger(SignerFactoryRegisterImpl.class);

    private P11CryptServiceFactory p11CryptServiceFactory;

    private ConcurrentLinkedDeque<SignerFactory> services =
            new ConcurrentLinkedDeque<SignerFactory>();

    public void setP11CryptServiceFactory(
            final P11CryptServiceFactory p11CryptServiceFactory) {
        this.p11CryptServiceFactory = p11CryptServiceFactory;
    }

    public void bindService(
            final SignerFactory service) {
        //might be null if dependency is optional
        if (service == null) {
            LOG.info("bindService invoked with null.");
            return;
        }

        boolean replaced = services.remove(service);
        services.add(service);

        String action = replaced
                ? "replaced"
                : "added";
        LOG.info("{} SignerFactory binding for {}", action, service);
    }

    public void unbindService(
            final SignerFactory service) {
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
    public ConcurrentContentSigner newSigner(
            final SecurityFactory securityFactory,
            final String type,
            final SignerConf conf,
            final X509Certificate[] certificateChain)
    throws ObjectCreationException {
        ParamUtil.requireNonBlank("type", type);

        if ("PKCS12".equalsIgnoreCase(type) || "JKS".equalsIgnoreCase(type)) {
            return newPkcs12OrJksSigner(securityFactory, type, conf, certificateChain);
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

    private ConcurrentContentSigner newPkcs12OrJksSigner(
            final SecurityFactory securityFactory,
            final String type,
            final SignerConf conf,
            final X509Certificate[] certificateChain)
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
            SoftTokenContentSignerBuilder signerBuilder = new SoftTokenContentSignerBuilder(
                    type, keystoreStream, password, keyLabel, password, certificateChain);

            AlgorithmIdentifier signatureAlgId;
            if (conf.getHashAlgo() == null) {
                signatureAlgId = AlgorithmUtil.getSignatureAlgoId(null, conf);
            } else {
                PublicKey pubKey = signerBuilder.getCert().getPublicKey();
                signatureAlgId = AlgorithmUtil.getSignatureAlgoId(pubKey, conf);
            }

            return signerBuilder.createSigner(signatureAlgId, parallelism,
                    securityFactory.getRandom4Sign());
        } catch (NoSuchAlgorithmException | OperatorCreationException | NoSuchPaddingException
                | XiSecurityException ex) {
            throw new ObjectCreationException(String.format("%s: %s",
                    ex.getClass().getName(), ex.getMessage()));
        }
    }

    public ConcurrentContentSigner newPkcs11Signer(
            final SecurityFactory securityFactory,
            final String type,
            final SignerConf conf,
            final X509Certificate[] certificateChain)
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
        Integer slotIndex = (str == null)
                ? null
                : Integer.parseInt(str);

        str = conf.getConfValue("slot-id");
        Long slotId = (str == null)
                ? null
                : Long.parseLong(str);

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
            P11Module module = p11Service.getModule();
            P11SlotIdentifier p11SlotId = (slotId != null)
                    ? module.getSlotIdForId(slotId)
                    : module.getSlotIdForIndex(slotIndex);
            slot = module.getSlot(p11SlotId);
        } catch (P11TokenException | XiSecurityException ex) {
            throw new ObjectCreationException(ex.getMessage(), ex);
        }

        P11ObjectIdentifier p11ObjId = (keyId != null)
                ? slot.getObjectIdForId(keyId)
                : slot.getObjectIdForLabel(keyLabel);
        if (p11ObjId == null) {
            String str2 = (keyId != null)
                    ? "id " + Hex.toHexString(keyId)
                    : "label " + keyLabel;
            throw new ObjectCreationException("cound not find identity with " + str2);
        }
        P11EntityIdentifier entityId = new P11EntityIdentifier(slot.getSlotId(), p11ObjId);

        try {
            AlgorithmIdentifier signatureAlgId;
            if (conf.getHashAlgo() == null) {
                signatureAlgId = AlgorithmUtil.getSignatureAlgoId(null, conf);
            } else {
                PublicKey pubKey = slot.getIdentity(p11ObjId).getPublicKey();
                signatureAlgId = AlgorithmUtil.getSignatureAlgoId(pubKey, conf);
            }

            P11ContentSignerBuilder signerBuilder = new P11ContentSignerBuilder(
                    p11Service, securityFactory, entityId, certificateChain);
            return signerBuilder.createSigner(signatureAlgId, parallelism);
        } catch (P11TokenException | NoSuchAlgorithmException | XiSecurityException ex) {
            throw new ObjectCreationException(ex.getMessage(), ex);
        }
    }

}
