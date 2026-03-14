// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.security.SignAlgo;
import org.xipki.security.composite.CompositeSigSuite;
import org.xipki.security.composite.CompositeSigUtil;
import org.xipki.security.sign.Signer;
import org.xipki.security.util.DigestOutputStream;
import org.xipki.util.codec.Args;
import org.xipki.util.io.IoUtil;

import java.io.IOException;
import java.io.OutputStream;

/**
 * PKCS#12 Composite MLDSA signer.
 *
 * @author Lijun Liao (xipki)
 */
public class P12CompositeMLDSASigner implements Signer {

  private final SignAlgo signAlgo;

  private final CompositeSigSuite algoSuite;

  private final byte[] encodedX509AlgId;

  private final DigestOutputStream os;

  private final Signer pqcSigner;

  private final Signer tradSigner;

  private final MyX509Signer x509Signer;

  private final byte[] context;

  public P12CompositeMLDSASigner(SignAlgo signAlgo, Signer pqcSigner, Signer tradSigner) {
    this.context = new byte[0]; // current no context is supported.
    this.pqcSigner = Args.notNull(pqcSigner, "pqcSigner");
    this.tradSigner = Args.notNull(tradSigner, "tradSigner");

    this.signAlgo = Args.notNull(signAlgo, "signAlgo");
    if (!signAlgo.isCompositeMLDSA()) {
      throw new IllegalArgumentException(signAlgo + " is not composite MLDSA");
    }

    try {
      this.encodedX509AlgId = signAlgo.algorithmIdentifier().getEncoded();
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }

    this.algoSuite = signAlgo.compositeSigAlgoSuite();
    this.x509Signer = new MyX509Signer();
    this.os = new DigestOutputStream(algoSuite.ph().createDigest());
  }

  @Override
  public ContentSigner x509Signer() {
    return x509Signer;
  }

  @Override
  public byte[] getEncodedX509AlgId() {
    return encodedX509AlgId.clone();
  }

  private class MyX509Signer implements ContentSigner {

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return signAlgo.algorithmIdentifier();
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

}
