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

package org.xipki.commons.security.pkcs12.internal;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Base64;
import org.xipki.commons.common.ObjectCreationException;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.password.api.PasswordResolver;
import org.xipki.commons.password.api.PasswordResolverException;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.SignerConf;
import org.xipki.commons.security.api.SignerFactory;
import org.xipki.commons.security.api.exception.XiSecurityException;
import org.xipki.commons.security.api.util.AlgorithmUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignerFactoryImpl implements SignerFactory {

    private SecurityFactory securityFactory;

    @Override
    public boolean canCreateSigner(
            final String type) {
        return "PKCS12".equalsIgnoreCase(type) || "JKS".equalsIgnoreCase(type);
    }

    @Override
    public ConcurrentContentSigner newSigner(
            final String type,
            final SignerConf conf,
            final X509Certificate[] certificateChain)
    throws ObjectCreationException {
        if (!canCreateSigner(type)) {
            throw new ObjectCreationException("unknown cert signer type '" + type + "'");
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

    public void setSecurityFactory(
            final SecurityFactory securityFactory) {
        this.securityFactory = securityFactory;
    }

}
