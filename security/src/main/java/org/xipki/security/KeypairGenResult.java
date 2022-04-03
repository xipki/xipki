/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.util.Args;

/**
 * Abstract class of the result of Keypair generation.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class KeypairGenResult {

    private final PrivateKeyInfo privateKey;

    private final SubjectPublicKeyInfo publicKey;

    public KeypairGenResult(PrivateKeyInfo privateKey, SubjectPublicKeyInfo publicKey) {
        this.privateKey = Args.notNull(privateKey, "privateKey");
        this.publicKey = Args.notNull(publicKey, "publicKey");
    }

    public PrivateKeyInfo getPrivateKey() {
        return privateKey;
    }

    public SubjectPublicKeyInfo getPublicKey() {
        return publicKey;
    }

}
