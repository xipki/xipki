/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api.p11;

/**
 * @author Lijun Liao
 */

public class P11SlotIdentifier implements Comparable<P11SlotIdentifier>
{
    private final Integer slotIndex;
    private final Long slotId;

    public P11SlotIdentifier(Integer slotIndex, Long slotId)
    {
        if(slotIndex == null && slotId == null)
        {
            throw new IllegalArgumentException("at least one of slotIndex an slotId must be non-null");
        }
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

        if(b instanceof P11SlotIdentifier == false)
        {
            return false;
        }

        if(this == b)
        {
            return true;
        }

        P11SlotIdentifier another = (P11SlotIdentifier) b;
        return (this.slotIndex == another.slotIndex || this.slotId == another.slotId);
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        if(slotIndex != null)
        {
            sb.append("slot-index: ").append(slotIndex);
            if(slotId != null)
            {
                sb.append(", ");
            }
        }
        if(slotId != null)
        {
            sb.append("slot-id: ").append(slotId);
        }
        return sb.toString();
    }

    @Override
    public int compareTo(P11SlotIdentifier o)
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
