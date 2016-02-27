/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.commons.security.api.util;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignerConfUtil {

    private SignerConfUtil() {
    }

    public static String getPkcs11SignerConfWithoutAlgo(
            final String pkcs11ModuleName,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId,
            final int parallelism) {
        ParamUtil.assertNotNull("keyId", keyId);

        ConfPairs conf = new ConfPairs();
        conf.putPair("parallelism", Integer.toString(parallelism));

        if (pkcs11ModuleName != null && pkcs11ModuleName.length() > 0) {
            conf.putPair("module", pkcs11ModuleName);
        }

        if (slotId.getSlotId() != null) {
            conf.putPair("slot-id", slotId.getSlotId().toString());
        } else {
            conf.putPair("slot", slotId.getSlotIndex().toString());
        }

        if (keyId.getKeyId() != null) {
            conf.putPair("key-id", Hex.toHexString(keyId.getKeyId()));
        }

        if (keyId.getKeyLabel() != null) {
            conf.putPair("key-label", keyId.getKeyLabel());
        }

        return conf.getEncoded();
    }

    public static String getKeystoreSignerConfWithoutAlgo(
            final String keystoreFile,
            final String password,
            final int parallelism) {
        ParamUtil.assertNotBlank("keystoreFile", keystoreFile);
        ParamUtil.assertNotBlank("password", password);

        ConfPairs conf = new ConfPairs("password", password);
        conf.putPair("parallelism", Integer.toString(parallelism));
        conf.putPair("keystore", "file:" + keystoreFile);
        return conf.getEncoded();
    }

    public static String getKeystoreSignerConfWithoutAlgo(
            final String keystoreFile,
            final String password) {
        ParamUtil.assertNotBlank("keystoreFile", keystoreFile);
        ParamUtil.assertNotBlank("password", password);

        ConfPairs conf = new ConfPairs("password", password);
        conf.putPair("parallelism", "1");
        conf.putPair("keystore", "file:" + keystoreFile);
        return conf.getEncoded();
    }

    public static String signerConfToString(
            final String signerConf,
            final boolean verbose,
            final boolean ignoreSensitiveInfo) {
        String localSignerConf = signerConf;
        if (ignoreSensitiveInfo) {
            localSignerConf = eraseSensitiveData(localSignerConf);
        }

        if (verbose || localSignerConf.length() < 101) {
            return localSignerConf;
        } else {
            return new StringBuilder().append(localSignerConf.substring(0, 97))
                    .append("...").toString();
        }
    }

    public static String getPkcs11SignerConf(
            final String pkcs11ModuleName,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId,
            final String signatureAlgorithm,
            final int parallelism) {
        ParamUtil.assertNotNull("algo", signatureAlgorithm);
        ParamUtil.assertNotNull("keyId", keyId);

        ConfPairs conf = new ConfPairs("algo", signatureAlgorithm);
        conf.putPair("parallelism", Integer.toString(parallelism));

        if (pkcs11ModuleName != null && pkcs11ModuleName.length() > 0) {
            conf.putPair("module", pkcs11ModuleName);
        }

        if (slotId.getSlotId() != null) {
            conf.putPair("slot-id", slotId.getSlotId().toString());
        } else {
            conf.putPair("slot", slotId.getSlotIndex().toString());
        }

        if (keyId.getKeyId() != null) {
            conf.putPair("key-id", Hex.toHexString(keyId.getKeyId()));
        }

        if (keyId.getKeyLabel() != null) {
            conf.putPair("key-label", keyId.getKeyLabel());
        }

        return conf.getEncoded();
    }

    public static String getKeystoreSignerConf(
            final InputStream keystoreStream,
            final String password,
            final String signatureAlgorithm,
            final int parallelism)
    throws IOException {
        ParamUtil.assertNotNull("keystoreStream", keystoreStream);
        ParamUtil.assertNotBlank("password", password);
        ParamUtil.assertNotNull("signatureAlgorithm", signatureAlgorithm);

        ConfPairs conf = new ConfPairs("password", password);
        conf.putPair("algo", signatureAlgorithm);
        conf.putPair("parallelism", Integer.toString(parallelism));
        conf.putPair("keystore", "base64:" + Base64.toBase64String(IoUtil.read(keystoreStream)));
        return conf.getEncoded();
    }

    private static String eraseSensitiveData(
            final String conf) {
        if (conf == null || !conf.contains("password?")) {
            return conf;
        }

        try {
            ConfPairs pairs = new ConfPairs(conf);
            String value = pairs.getValue("password");
            if (value != null && !StringUtil.startsWithIgnoreCase(value, "PBE:")) {
                pairs.putPair("password", "<sensitve>");
            }
            return pairs.getEncoded();
        } catch (Exception ex) {
            return conf;
        }
    }

}
