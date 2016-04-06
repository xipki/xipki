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

package org.xipki.commons.security.shell.p11;

import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Enumeration;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.xipki.commons.console.karaf.completer.HashAlgCompleter;
import org.xipki.commons.security.api.SignatureAlgoControl;
import org.xipki.commons.security.api.XiSecurityConstants;
import org.xipki.commons.security.api.util.AlgorithmUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-tk", name = "provider-test",
        description = "test the Xipki JCA/JCE provider")
@Service
public class P11ProviderTestCmd extends P11SecurityCommandSupport {

    @Option(name = "--verbose", aliases = "-v",
            description = "show object information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Option(name = "--hash",
            description = "hash algorithm name")
    @Completion(HashAlgCompleter.class)
    protected String hashAlgo = "SHA256";

    @Option(name = "--rsa-mgf1",
            description = "whether to use the RSAPSS MGF1 for the POPO computation\n"
                    + "(only applied to RSA key)")
    private Boolean rsaMgf1 = Boolean.FALSE;

    @Option(name = "--ecdsa-plain",
            description = "whether to use the Plain DSA for the POPO computation\n"
                    + "(only applied to ECDSA key)")
    private Boolean ecdsaPlain = Boolean.FALSE;

    @Override
    protected Object doExecute()
    throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS11", XiSecurityConstants.PROVIDER_NAME_XIPKI);
        ks.load(null, null);
        if (verbose.booleanValue()) {
            println("available aliases:");
            Enumeration<?> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias2 = (String) aliases.nextElement();
                println("    " + alias2);
            }
        }

        String alias = getAlias();
        println("alias: " + alias);
        PrivateKey key = (PrivateKey) ks.getKey(alias, null);
        if (key == null) {
            println("could not find key with alias '" + alias + "'");
            return null;
        }

        Certificate cert = ks.getCertificate(alias);
        if (cert == null) {
            println("could not find certificate to verify signature");
            return null;
        }
        PublicKey pubKey = cert.getPublicKey();

        String sigAlgo = getSignatureAlgo(pubKey);
        println("signature algorithm: " + sigAlgo);
        Signature sig = Signature.getInstance(sigAlgo, XiSecurityConstants.PROVIDER_NAME_XIPKI);
        sig.initSign(key);

        byte[] data = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        sig.update(data);
        byte[] signature = sig.sign(); // CHECKSTYLE:SKIP
        println("signature created successfully");

        Signature ver = Signature.getInstance(sigAlgo, "BC");
        ver.initVerify(pubKey);
        ver.update(data);
        boolean valid = ver.verify(signature);
        println("signature valid: " + valid);
        return null;
    }

    private String getAlias() {
        StringBuilder sb = new StringBuilder(100);
        sb.append(moduleName).append("#slotindex-").append(slotIndex);
        if (label != null) {
            sb.append("#keylabel-").append(label);
        } else {
            sb.append("#keyid-").append(id.toUpperCase());
        }
        return sb.toString();
    }

    private String getSignatureAlgo(
            final PublicKey pubKey)
    throws NoSuchAlgorithmException {
        SignatureAlgoControl algoControl = new SignatureAlgoControl(rsaMgf1, ecdsaPlain);
        AlgorithmIdentifier sigAlgoId = AlgorithmUtil.getSignatureAlgoId(pubKey, hashAlgo,
                algoControl);
        return AlgorithmUtil.getSignatureAlgoName(sigAlgoId);
    }

}
