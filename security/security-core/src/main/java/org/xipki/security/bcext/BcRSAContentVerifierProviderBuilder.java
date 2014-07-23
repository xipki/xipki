/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.bcext;

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
import org.xipki.security.SignerUtil;

/**
 * @author Lijun Liao
 */

public class BcRSAContentVerifierProviderBuilder
    extends BcContentVerifierProviderBuilder
{
    private DigestAlgorithmIdentifierFinder digestAlgorithmFinder;

    public BcRSAContentVerifierProviderBuilder(DigestAlgorithmIdentifierFinder digestAlgorithmFinder)
    {
        this.digestAlgorithmFinder = digestAlgorithmFinder;
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId)
    throws OperatorCreationException
    {
        AlgorithmIdentifier digAlgId = digestAlgorithmFinder.find(sigAlgId);
        Digest dig = digestProvider.get(digAlgId);

        if(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgId.getAlgorithm()))
        {
            return SignerUtil.createPSSRSASigner(sigAlgId);
        }
        else
        {
            return new RSADigestSigner(dig);
        }
    }

    protected AsymmetricKeyParameter extractKeyParameters(SubjectPublicKeyInfo publicKeyInfo)
    throws IOException
    {
        return PublicKeyFactory.createKey(publicKeyInfo);
    }
}
