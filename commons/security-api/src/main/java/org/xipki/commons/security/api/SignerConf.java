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

package org.xipki.commons.security.api;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignerConf {

    private final ConfPairs confPairs;

    private final HashAlgoType hashAlgo;

    private final SignatureAlgoControl signatureAlgoControl;

    public SignerConf(
            final String conf) {
        this.hashAlgo = null;
        this.signatureAlgoControl = null;
        ParamUtil.requireNonBlank("conf", conf);
        this.confPairs = new ConfPairs(conf);
        if (getConfValue("algo") == null) {
            throw new IllegalArgumentException("confWithoutAlgo must contain the entry 'algo'");
        }
    }

    public SignerConf(
            final String confWithoutAlgo,
            final HashAlgoType hashAlgo,
            final SignatureAlgoControl signatureAlgoControl) {
        ParamUtil.requireNonBlank("confWithoutAlgo", confWithoutAlgo);
        this.hashAlgo = ParamUtil.requireNonNull("hashAlgo", hashAlgo);
        this.signatureAlgoControl = signatureAlgoControl;
        this.confPairs = new ConfPairs(confWithoutAlgo);
        if (getConfValue("algo") != null) {
            throw new IllegalArgumentException("confWithoutAlgo must not contain the entry 'algo'");
        }
    }

    public HashAlgoType getHashAlgo() {
        return hashAlgo;
    }

    public SignatureAlgoControl getSignatureAlgoControl() {
        return signatureAlgoControl;
    }

    public void putConfEntry(
            final String name,
            final String value) {
        confPairs.putPair(name, value);
    }

    public void removeConfEntry(
            final String name) {
        confPairs.removePair(name);
    }

    public String getConfValue(String name) {
        return confPairs.getValue(name);
    }

    public String getConf() {
        return confPairs.getEncoded();
    }

    @Override
    public String toString() {
        return toString(true, true);
    }

    public String toString(
            final boolean verbose,
            final boolean ignoreSensitiveInfo) {
        String conf = getConf();
        if (ignoreSensitiveInfo) {
            conf = eraseSensitiveData(conf);
        }

        StringBuilder sb = new StringBuilder(conf.length() + 50);
        sb.append("conf: ");
        sb.append(conf);
        if (hashAlgo != null) {
            sb.append("\nhash algo: ").append(hashAlgo.getName());
        }

        if (signatureAlgoControl != null) {
            sb.append("\nsiganture algo control: ").append(signatureAlgoControl);
        }

        return sb.toString();
    }

    public static String toString(
            final String signerConf,
            final boolean verbose,
            final boolean ignoreSensitiveInfo) {
        String tmpSignerConf = ParamUtil.requireNonBlank("signerConf", signerConf);
        if (ignoreSensitiveInfo) {
            tmpSignerConf = eraseSensitiveData(tmpSignerConf);
        }

        if (verbose || tmpSignerConf.length() < 101) {
            return tmpSignerConf;
        } else {
            return new StringBuilder().append(tmpSignerConf.substring(0, 97))
                    .append("...").toString();
        }
    }

    public static SignerConf getKeystoreSignerConf(
            final InputStream keystoreStream,
            final String password,
            final String signatureAlgorithm,
            final int parallelism)
    throws IOException {
        ParamUtil.requireNonNull("keystoreStream", keystoreStream);
        ParamUtil.requireNonBlank("password", password);
        ParamUtil.requireNonNull("signatureAlgorithm", signatureAlgorithm);
        ParamUtil.requireMin("parallelism", parallelism, 1);

        ConfPairs conf = new ConfPairs("password", password);
        conf.putPair("algo", signatureAlgorithm);
        conf.putPair("parallelism", Integer.toString(parallelism));
        conf.putPair("keystore", "base64:" + Base64.toBase64String(IoUtil.read(keystoreStream)));
        return new SignerConf(conf.getEncoded());
    }

    public static SignerConf getKeystoreSignerConf(
            final String keystoreFile,
            final String password,
            final int parallelism,
            final HashAlgoType hashAlgo,
            final SignatureAlgoControl signatureAlgoControl) {
        ParamUtil.requireNonBlank("keystoreFile", keystoreFile);
        ParamUtil.requireNonBlank("password", password);
        ParamUtil.requireMin("parallelism", parallelism, 1);
        ParamUtil.requireNonNull("hashAlgo", hashAlgo);

        ConfPairs conf = new ConfPairs("password", password);
        conf.putPair("parallelism", Integer.toString(parallelism));
        conf.putPair("keystore", "file:" + keystoreFile);
        return new SignerConf(conf.getEncoded(), hashAlgo, signatureAlgoControl);
    }

    public static SignerConf getPkcs11SignerConf(
            final String pkcs11ModuleName,
            final Integer slotIndex,
            final Long slotId,
            final String keyLabel,
            final byte[] keyId,
            final int parallelism,
            final HashAlgoType hashAlgo,
            final SignatureAlgoControl signatureAlgoControl) {
        ParamUtil.requireMin("parallelism", parallelism, 1);
        ParamUtil.requireNonNull("hashAlgo", hashAlgo);

        if (slotIndex == null && slotId == null) {
            throw new IllegalArgumentException(
                    "at least one of slotIndex and slotId must not be null");
        }
        if (keyId == null && keyLabel == null) {
            throw new IllegalArgumentException(
                    "at least one of keyId and keyLabel must not be null");
        }

        ConfPairs conf = new ConfPairs();
        conf.putPair("parallelism", Integer.toString(parallelism));

        if (pkcs11ModuleName != null && pkcs11ModuleName.length() > 0) {
            conf.putPair("module", pkcs11ModuleName);
        }

        if (slotId != null) {
            conf.putPair("slot-id", slotId.toString());
        }

        if (slotIndex != null) {
            conf.putPair("slot", slotIndex.toString());
        }

        if (keyId != null) {
            conf.putPair("key-id", Hex.toHexString(keyId));
        }

        if (keyLabel != null) {
            conf.putPair("key-label", keyLabel);
        }

        return new SignerConf(conf.getEncoded(), hashAlgo, signatureAlgoControl);
    }

    public static SignerConf getPkcs11SignerConf(
            final String pkcs11ModuleName,
            final Integer slotIndex,
            final Long slotId,
            final String keyLabel,
            final byte[] keyId,
            final String signatureAlgorithm,
            final int parallelism) {
        ParamUtil.requireMin("parallelism", parallelism, 1);
        ParamUtil.requireNonNull("algo", signatureAlgorithm);
        if (slotIndex == null && slotId == null) {
            throw new IllegalArgumentException(
                    "at least one of slotIndex and slotId must not be null");
        }
        if (keyId == null && keyLabel == null) {
            throw new IllegalArgumentException(
                    "at least one of keyId and keyLabel must not be null");
        }

        ConfPairs conf = new ConfPairs("algo", signatureAlgorithm);
        conf.putPair("parallelism", Integer.toString(parallelism));

        if (pkcs11ModuleName != null && pkcs11ModuleName.length() > 0) {
            conf.putPair("module", pkcs11ModuleName);
        }

        if (slotId != null) {
            conf.putPair("slot-id", slotId.toString());
        }

        if (slotIndex != null) {
            conf.putPair("slot", slotIndex.toString());
        }

        if (keyId != null) {
            conf.putPair("key-id", Hex.toHexString(keyId));
        }

        if (keyLabel != null) {
            conf.putPair("key-label", keyLabel);
        }

        return new SignerConf(conf.getEncoded());
    }

    public static SignerConf getKeystoreSignerConfWithoutAlgo(
            final String keystoreFile,
            final String password,
            final HashAlgoType hashAlgo,
            final SignatureAlgoControl signatureAlgoControl) {
        ParamUtil.requireNonBlank("keystoreFile", keystoreFile);
        ParamUtil.requireNonBlank("password", password);
        ParamUtil.requireNonNull("hashAlgo", hashAlgo);

        ConfPairs conf = new ConfPairs("password", password);
        conf.putPair("parallelism", "1");
        conf.putPair("keystore", "file:" + keystoreFile);
        return new SignerConf(conf.getEncoded(), hashAlgo, signatureAlgoControl);
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
