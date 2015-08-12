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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.StringTokenizer;

import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.scep4j.crypto.HashAlgoType;
import org.xipki.scep4j.transaction.CACapability;

/**
 * @author Lijun Liao
 */

public class CACaps
{
    private static final Logger LOG = LoggerFactory.getLogger(CACaps.class);

    private byte[] bytes;
    private final Set<CACapability> capabilities;

    public CACaps()
    {
        this.capabilities = new HashSet<CACapability>();
    }

    public CACaps(
            final Set<CACapability> capabilities)
    {
        if(capabilities == null)
        {
            this.capabilities = new HashSet<CACapability>();
        }else
        {
            this.capabilities = new HashSet<CACapability>(capabilities);
        }
        refresh();
    }

    public Set<CACapability> getCapabilities()
    {
        return Collections.unmodifiableSet(capabilities);
    }

    public void removeCapabilities(
            final CACaps caCaps)
    {
        this.capabilities.retainAll(caCaps.capabilities);
        refresh();
    }

    public void addCapability(
            final CACapability cap)
    {
        if(cap != null)
        {
            capabilities.add(cap);
            refresh();
        }
    }

    public void removeCapability(
            final CACapability cap)
    {
        if(cap != null)
        {
            capabilities.remove(cap);
            refresh();
        }
    }

    public boolean containsCapability(
            final CACapability cap)
    {
        return capabilities.contains(cap);
    }

    public static CACaps getInstance(
            final String scepMessage)
    {
        CACaps ret = new CACaps();
        if(scepMessage == null || scepMessage.isEmpty())
        {
            return ret;
        }

        StringTokenizer st = new StringTokenizer(scepMessage, "\r\n");

        while(st.hasMoreTokens())
        {
            String m = st.nextToken();
            CACapability cap = CACapability.valueForText(m);
            if(cap == null)
            {
                LOG.warn("ignore unknown CACap '{}'", m);
            } else
            {
                ret.addCapability(cap);
            }
        }
        return ret;
    }

    @Override
    public String toString()
    {
        return toScepMessage();
    }

    public String toScepMessage()
    {
        if(capabilities.isEmpty())
        {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for(CACapability cap : capabilities)
        {
            sb.append(cap.getText()).append("\n");
        }
        sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

    public boolean supportsPost()
    {
        return capabilities.contains(CACapability.POSTPKIOperation);
    }

    public HashAlgoType getMostSecureHashAlgo()
    {
        if(capabilities.contains(CACapability.SHA512))
        {
            return HashAlgoType.SHA512;
        } else if(capabilities.contains(CACapability.SHA256))
        {
            return HashAlgoType.SHA256;
        } else if(capabilities.contains(CACapability.SHA1))
        {
            return HashAlgoType.SHA1;
        } else
        {
            return HashAlgoType.MD5;
        }
    }

    private void refresh()
    {
        if(capabilities != null)
        {
            this.bytes = toString().getBytes();
        }
    }

    @Override
    public boolean equals(
            final Object other)
    {
        if(other instanceof CACaps == false)
        {
            return false;
        }

        CACaps b = (CACaps) other;
        return capabilities.equals(b.capabilities);
    }

    public byte[] getBytes()
    {
        return Arrays.clone(bytes);
    }
}
