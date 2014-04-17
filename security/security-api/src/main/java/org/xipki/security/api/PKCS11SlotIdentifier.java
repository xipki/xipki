/*
 * Copyright 2014 xipki.org
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

package org.xipki.security.api;

public class PKCS11SlotIdentifier implements Comparable<PKCS11SlotIdentifier>
{
    private final Integer slotIndex;
    private final Long slotId;

    public PKCS11SlotIdentifier(Integer slotIndex, Long slotId)
    {
        this.slotIndex = slotIndex;
        this.slotId = slotId;
    }

    public Integer getSlotIndex()
    {
        return slotIndex;
    }

    public Long getSlotId()
    {
        return slotId;
    }

    @Override
    public boolean equals(Object b)
    {
        if(this == b)
        {
            return true;
        }

        if(b instanceof PKCS11SlotIdentifier == false)
        {
            return false;
        }

        if(this == b)
        {
            return true;
        }

        PKCS11SlotIdentifier another = (PKCS11SlotIdentifier) b;
        return (this.slotIndex == another.slotIndex || this.slotId == another.slotId);
    }

    @Override
    public String toString()
    {
        return "index: " + slotIndex + ", slot-id: " + slotId;
    }

    @Override
    public int compareTo(PKCS11SlotIdentifier o)
    {
        if(this == o)
        {
            return 0;
        }

        if(slotIndex != null)
        {
            if(o.slotIndex != null)
            {
                int sign = slotIndex - o.slotIndex;
                if(sign > 0)
                {
                    return 1;
                }
                else if(sign < 0)
                {
                    return -1;
                }
                else
                {
                    return 0;
                }
            }
            else
            {
                return -1;
            }
        }

        return 0;
    }
}
