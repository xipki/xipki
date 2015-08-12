/*
 * Copyright (c) 2015 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.scep4j.message;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.xipki.scep4j.exception.MessageDecodingException;
import org.xipki.scep4j.util.ParamUtil;

/**
 * @author Lijun Liao
 */

public final class EnvelopedDataDecryptor
{
    private final List<EnvelopedDataDecryptorInstance> decryptors;

    public EnvelopedDataDecryptor(
            final List<EnvelopedDataDecryptorInstance> decryptors)
    {
        ParamUtil.assertNotEmpty("decryptors", decryptors);
        this.decryptors = new ArrayList<EnvelopedDataDecryptorInstance>(decryptors);
    }

    public EnvelopedDataDecryptor(
            final EnvelopedDataDecryptorInstance decryptor)
    {
        ParamUtil.assertNotNull("decryptor", decryptor);
        this.decryptors = new ArrayList<EnvelopedDataDecryptorInstance>(1);
        this.decryptors.add(decryptor);
    }

    public byte[] decrypt(
            final CMSEnvelopedData envData)
    throws MessageDecodingException
    {
        final RecipientInformationStore recipientInfos = envData.getRecipientInfos();
        RecipientInformation recipientInfo = null;
        EnvelopedDataDecryptorInstance decryptor = null;
        for(EnvelopedDataDecryptorInstance m : decryptors)
        {
            recipientInfo = recipientInfos.get(m.getRecipientId());
            if(recipientInfo != null)
            {
                decryptor = m;
                break;
            }
        }

        if(recipientInfo == null)
        {
            throw new MessageDecodingException(
                    "missing expected key transfer recipient");
        }

        try
        {
            return recipientInfo.getContent(decryptor.getRecipient());
        }catch(CMSException e)
        {
            throw new MessageDecodingException("could not decrypt the envelopedData");
        }
    }

}
