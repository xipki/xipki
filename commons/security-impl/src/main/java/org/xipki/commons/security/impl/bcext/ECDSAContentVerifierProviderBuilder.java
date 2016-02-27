// #THIRDPARTY# BouncyCastle

/*
 * Copied from BouncyCastle under license MIT
 */

package org.xipki.commons.security.impl.bcext;

import java.io.IOException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentVerifierProviderBuilder;

public class ECDSAContentVerifierProviderBuilder extends BcContentVerifierProviderBuilder {

    private DigestAlgorithmIdentifierFinder digestAlgorithmFinder;

    public ECDSAContentVerifierProviderBuilder(
            final DigestAlgorithmIdentifierFinder digestAlgorithmFinder) {
        this.digestAlgorithmFinder = digestAlgorithmFinder;
    }

    protected Signer createSigner(
            final AlgorithmIdentifier sigAlgId)
    throws OperatorCreationException {
        AlgorithmIdentifier digAlg = digestAlgorithmFinder.find(sigAlgId);
        if (digAlg == null) {
            throw new OperatorCreationException(
                    "could not retrieve digest algorithm from the signature algorithm "
                    + sigAlgId.getAlgorithm().getId());
        }
        Digest dig = digestProvider.get(digAlg);

        return new DSADigestSigner(new ECDSASigner(), dig);
    }

    protected AsymmetricKeyParameter extractKeyParameters(
            final SubjectPublicKeyInfo publicKeyInfo)
    throws IOException {
        return PublicKeyFactory.createKey(publicKeyInfo);
    }

}
