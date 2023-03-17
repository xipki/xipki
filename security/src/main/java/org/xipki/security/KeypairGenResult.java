// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.util.Args;

/**
 * Abstract class of the result of Keypair generation.
 *
 * @author Lijun Liao (xipki)
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
