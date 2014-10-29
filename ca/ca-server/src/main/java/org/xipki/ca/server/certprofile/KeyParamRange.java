/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.certprofile;

/**
 * @author Lijun Liao
 */

class KeyParamRange
{
    private final Integer min;
    private final Integer max;

    public KeyParamRange(Integer min, Integer max)
    {
        this.min = min;
        this.max = max;
    }

    public Integer getMin()
    {
        return min;
    }

    public Integer getMax()
    {
        return max;
    }

    public boolean match(int i)
    {
        if(min != null && i < min)
        {
            return false;
        }
        if(max != null && i > max)
        {
            return false;
        }

        return true;
    }
}
