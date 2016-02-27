// #THIRDPARTY# BouncyCastle

/*
 * Copied from BouncyCastle under license MIT
 */

package org.xipki.commons.security.impl.bcext;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;

public class ECDSAContentSignerBuilder extends BcContentSignerBuilder {

    public ECDSAContentSignerBuilder(
            final AlgorithmIdentifier sigAlgId,
            final AlgorithmIdentifier digAlgId) {
        super(sigAlgId, digAlgId);
    }

    protected Signer createSigner(
            final AlgorithmIdentifier sigAlgId,
            final AlgorithmIdentifier digAlgId)
    throws OperatorCreationException {
        Digest dig = digestProvider.get(digAlgId);

        return new DSADigestSigner(new ECDSASigner(), dig);
    }

}
