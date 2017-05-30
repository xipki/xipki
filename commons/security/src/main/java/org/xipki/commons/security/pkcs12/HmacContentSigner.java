/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.commons.security.pkcs12;

import java.io.IOException;
import java.io.OutputStream;

import javax.crypto.SecretKey;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.HashAlgoType;
import org.xipki.commons.security.util.AlgorithmUtil;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class HmacContentSigner implements ContentSigner {

    private class HmacOutputStream extends OutputStream {

        @Override
        public void write(int bb) throws IOException {
            hmac.update((byte) bb);
        }

        @Override
        public void write(byte[] bytes) throws IOException {
            hmac.update(bytes, 0, bytes.length);
        }

        @Override
        public void write(byte[] bytes, int off, int len) throws IOException {
            hmac.update(bytes, off, len);
        }

    }

    private final AlgorithmIdentifier algorithmIdentifier;

    private final HmacOutputStream outputStream;

    private final HMac hmac;

    private final int outLen;

    public HmacContentSigner(AlgorithmIdentifier algorithmIdentifier,
            SecretKey signingKey) {
        this(null, algorithmIdentifier, signingKey);
    }

    public HmacContentSigner(HashAlgoType hashAlgo, AlgorithmIdentifier algorithmIdentifier,
            SecretKey signingKey) {
        this.algorithmIdentifier = ParamUtil.requireNonNull("algorithmIdentifier",
                algorithmIdentifier);
        ParamUtil.requireNonNull("signingKey", signingKey);
        if (hashAlgo == null) {
            hashAlgo = AlgorithmUtil.extractHashAlgoFromMacAlg(algorithmIdentifier);
        }

        this.hmac = new HMac(hashAlgo.createDigest());
        byte[] keyBytes = signingKey.getEncoded();
        this.hmac.init(new KeyParameter(keyBytes, 0, keyBytes.length));
        this.outLen = hmac.getMacSize();
        this.outputStream = new HmacOutputStream();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream() {
        hmac.reset();
        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        byte[] signature = new byte[outLen];
        hmac.doFinal(signature, 0);
        return signature;
    }

}
