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

package org.xipki.scep.message;

import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

/**
 * EnvelopedData decryptor.
 *
 * @author Lijun Liao
 */

public final class EnvelopedDataDecryptor {

  public static final class EnvelopedDataDecryptorInstance {

    private final RecipientId recipientId;

    private final Recipient recipient;

    public EnvelopedDataDecryptorInstance(X509Cert recipientCert, PrivateKey privKey) {
      Args.notNull(recipientCert, "recipientCert");
      Args.notNull(privKey, "privKey");

      this.recipientId = new KeyTransRecipientId(
          recipientCert.getIssuer(), recipientCert.getSerialNumber(), recipientCert.getSubjectKeyId());
      this.recipient = new JceKeyTransEnvelopedRecipient(privKey);
    }

    public Recipient getRecipient() {
      return recipient;
    }

    public RecipientId getRecipientId() {
      return recipientId;
    }

  }

  private final List<EnvelopedDataDecryptorInstance> decryptors;

  public EnvelopedDataDecryptor(List<EnvelopedDataDecryptorInstance> decryptors) {
    Args.notEmpty(decryptors, "decryptors");
    this.decryptors = new ArrayList<>(decryptors);
  }

  public EnvelopedDataDecryptor(EnvelopedDataDecryptorInstance decryptor) {
    Args.notNull(decryptor, "decryptor");
    this.decryptors = new ArrayList<>(1);
    this.decryptors.add(decryptor);
  }

  public byte[] decrypt(CMSEnvelopedData envData) throws MessageDecodingException {
    Args.notNull(envData, "envData");
    final RecipientInformationStore recipientInfos = envData.getRecipientInfos();
    RecipientInformation recipientInfo = null;
    EnvelopedDataDecryptorInstance decryptor = null;
    for (EnvelopedDataDecryptorInstance m : decryptors) {
      recipientInfo = recipientInfos.get(m.getRecipientId());
      if (recipientInfo != null) {
        decryptor = m;
        break;
      }
    }

    if (recipientInfo == null || decryptor == null) {
      throw new MessageDecodingException("missing expected key transfer recipient");
    }

    try {
      return recipientInfo.getContent(decryptor.getRecipient());
    } catch (CMSException ex) {
      throw new MessageDecodingException("could not decrypt the envelopedData");
    }
  }

}
