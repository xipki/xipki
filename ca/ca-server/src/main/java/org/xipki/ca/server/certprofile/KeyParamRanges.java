/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.certprofile;

import java.util.List;
import java.util.Map;

import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class KeyParamRanges
{
    private final Map<String, List<KeyParamRange>> ranges;

    public KeyParamRanges(Map<String, List<KeyParamRange>> ranges)
    {
        ParamChecker.assertNotNull("ranges", ranges);
        this.ranges = ranges;
    }

    public List<KeyParamRange> getRanges(String name)
    {
        return ranges.get(name);
    }

}
