// #THIRDPARTY# android team

/*
 * Copied from BouncyCastle under license MIT
 */

package org.xipki.commons.security.bcext;

import java.io.IOException;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentVerifierProviderBuilder;
import org.xipki.commons.security.api.util.SignerUtil;

public class BcRSAContentVerifierProviderBuilder extends BcContentVerifierProviderBuilder {

    private DigestAlgorithmIdentifierFinder digestAlgorithmFinder;

    public BcRSAContentVerifierProviderBuilder(
            final DigestAlgorithmIdentifierFinder digestAlgorithmFinder) {
        this.digestAlgorithmFinder = digestAlgorithmFinder;
    }

    protected Signer createSigner(
            final AlgorithmIdentifier sigAlgId)
    throws OperatorCreationException {
        AlgorithmIdentifier digAlgId = digestAlgorithmFinder.find(sigAlgId);
        Digest dig = digestProvider.get(digAlgId);

        if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgId.getAlgorithm())) {
            return SignerUtil.createPSSRSASigner(sigAlgId);
        } else {
            return new RSADigestSigner(dig);
        }
    }

    protected AsymmetricKeyParameter extractKeyParameters(
            final SubjectPublicKeyInfo publicKeyInfo)
    throws IOException {
        return PublicKeyFactory.createKey(publicKeyInfo);
    }

}
