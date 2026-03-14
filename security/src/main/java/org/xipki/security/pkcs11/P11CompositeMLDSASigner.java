// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.composite.CompositeSigSuite;
import org.xipki.security.composite.CompositeSigUtil;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.sign.Signer;
import org.xipki.security.sign.SignerConf;
import org.xipki.security.util.DigestOutputStream;
import org.xipki.util.codec.Args;
import org.xipki.util.io.IoUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * PKCS#11 {@link Signer} for composite signers.
 *
 * @author Lijun Liao (xipki)
 */
class P11CompositeMLDSASigner implements Signer {

  private final DigestOutputStream os;

  private final P11Signer pqcSigner;

  private final P11Signer tradSigner;

  private final CompositeSigSuite algoSuite;

  private final byte[] encodedX509AlgId;

  private final byte[] context;

  private final MyX509Signer x509Signer;

  private P11CompositeMLDSASigner(
      SecurityFactory securityFactory, P11CompositeKey identity, SignerConf conf,
      CompositeSigSuite algoSuite, byte[] context, SecureRandom rnd)
      throws XiSecurityException {
    this.context = context == null ? null : context.clone();
    this.os = new DigestOutputStream(algoSuite.ph().createDigest());
    this.algoSuite = Args.notNull(algoSuite, "algoSuite");

    try {
      this.encodedX509AlgId = algoSuite.algId().getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }

    this.pqcSigner = P11Signer.newInstance(securityFactory,
        identity.pqcKey(), conf, algoSuite.pqcVariant().signAlgo(),
        rnd, identity.pqcKey().publicKey(), algoSuite.label());
    this.tradSigner = P11Signer.newInstance(securityFactory,
        identity.tradKey(), conf, algoSuite.tradVariant().signAlgo(),
        rnd, identity.tradKey().publicKey());
    this.x509Signer = new MyX509Signer();
  }

  @Override
  public final byte[] getEncodedX509AlgId() {
    return Arrays.copyOf(encodedX509AlgId, encodedX509AlgId.length);
  }

  @Override
  public ContentSigner x509Signer() {
    return x509Signer;
  }

  private class MyX509Signer implements ContentSigner {

    @Override
    public final AlgorithmIdentifier getAlgorithmIdentifier() {
      return algoSuite.algId();
    }

    @Override
    public OutputStream getOutputStream() {
      os.reset();
      return os;
    }

    @Override
    public byte[] getSignature() {
      byte[] digestValue = os.digest();
      byte[] m_ = CompositeSigUtil.buildM_(algoSuite, context, digestValue);

      try {
        pqcSigner .x509Signer().getOutputStream().write(m_);
        tradSigner.x509Signer().getOutputStream().write(m_);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }

      byte[]  pqcSig =  pqcSigner.x509Signer().getSignature();
      byte[] tradSig = tradSigner.x509Signer().getSignature();
      return IoUtil.concatenate(pqcSig, tradSig);
    }
  }

  static P11CompositeMLDSASigner newInstance(
      SecurityFactory securityFactory, P11CompositeKey key, SignerConf conf,
      SignAlgo signAlgo, SecureRandom random, PublicKey publicKey)
      throws XiSecurityException {
    if (publicKey != null) {
      key.setPublicKey(publicKey);
    }
    return new P11CompositeMLDSASigner(securityFactory, key, conf,
        signAlgo.compositeSigAlgoSuite(), null, random);
  }

}
