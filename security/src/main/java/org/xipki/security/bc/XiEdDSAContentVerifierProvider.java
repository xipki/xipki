/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.security.bc;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.xipki.security.EdECConstants;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.1.0
 */

// CHECKSTYLE:SKIP
public class XiEdDSAContentVerifierProvider implements ContentVerifierProvider {

  //CHECKSTYLE:SKIP
  private class EdDSAContentVerifier implements ContentVerifier {

    private final String algorithm;

    private final AlgorithmIdentifier algId;

    private final ByteArrayOutputStream outstream;

    private final PublicKey verifyKey;

    private EdDSAContentVerifier(AlgorithmIdentifier algId, PublicKey verifyKey) {
      this.algId = algId;
      this.algorithm = EdECConstants.getKeyAlgNameForKeyAlg(algId);
      this.outstream = new ByteArrayOutputStream();
      this.verifyKey = verifyKey;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algId;
    }

    @Override
    public OutputStream getOutputStream() {
      outstream.reset();
      return outstream;
    }

    @Override
    public boolean verify(byte[] expected) {
      try {
        Signature sig = Signature.getInstance(algorithm, "BC");
        sig.initVerify(verifyKey);
        sig.update(outstream.toByteArray());
        return sig.verify(expected);
      } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException ex) {
        throw new RuntimeCryptoException(ex.getMessage());
      } catch (SignatureException ex) {
        return false;
      }
    }

  }

  private final PublicKey verifyKey;

  public XiEdDSAContentVerifierProvider(PublicKey verifyKey) {
    this.verifyKey = Args.notNull(verifyKey, "verifyKey");
  }

  @Override
  public boolean hasAssociatedCertificate() {
    return false;
  }

  @Override
  public X509CertificateHolder getAssociatedCertificate() {
    return null;
  }

  @Override
  public ContentVerifier get(AlgorithmIdentifier verifierAlgorithmIdentifier)
      throws OperatorCreationException {
    return new EdDSAContentVerifier(verifierAlgorithmIdentifier, verifyKey);
  }

}
