// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.scep.message;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.pkix.cms.CmsEnvelopedData;
import org.xipki.pkix.cms.CmsRecipient;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.util.exception.PkixException;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Enveloped Data Decryptor.
 *
 * @author Lijun Liao (xipki)
 */
public final class EnvelopedDataDecryptor {

  /**
   * Enveloped Data Decryptor Instance.
   */
  public static final class EnvelopedDataDecryptorInstance {

    private final X509Cert recipientCert;

    private final PrivateKey privKey;

    public EnvelopedDataDecryptorInstance(X509Cert recipientCert, PrivateKey privKey) {
      this.recipientCert = Args.notNull(recipientCert, "recipientCert");
      this.privKey = Args.notNull(privKey, "privKey");
    }

  }

  private final List<EnvelopedDataDecryptorInstance> decryptors;

  public EnvelopedDataDecryptor(List<EnvelopedDataDecryptorInstance> decryptors) {
    this.decryptors = new ArrayList<>(Args.notEmpty(decryptors, "decryptors"));
  }

  public EnvelopedDataDecryptor(EnvelopedDataDecryptorInstance decryptor) {
    this.decryptors = Collections.singletonList(Args.notNull(decryptor, "decryptor"));
  }

  public byte[] decrypt(CmsEnvelopedData envData) throws CodecException {
    Args.notNull(envData, "envData");
    for (EnvelopedDataDecryptorInstance m : decryptors) {
      CmsRecipient recipient = envData.getRecipient(m.recipientCert.getCert());
      if (recipient != null && recipient.getType() == CmsRecipient.Type.KEY_TRANS) {
        try {
          return recipient.decrypt(m.privKey);
        } catch (PkixException ex) {
          throw new CodecException("could not decrypt the envelopedData", ex);
        }
      }
    }

    throw new CodecException("missing expected key transfer recipient");
  }

}
