/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell.completer;

import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.xipki.console.karaf.DynamicEnumCompleter;

/**
 * @author Lijun Liao
 */

public class ECCurverNameCompleter extends DynamicEnumCompleter
{

    @Override
    protected Set<String> getEnums()
    {
        Set<String> curveNames = new HashSet<>();
        Enumeration<?> names = X962NamedCurves.getNames();
        while(names.hasMoreElements())
        {
            curveNames.add((String) names.nextElement());
        }

        names = SECNamedCurves.getNames();
        while(names.hasMoreElements())
        {
            curveNames.add((String) names.nextElement());
        }

        names = TeleTrusTNamedCurves.getNames();
        while(names.hasMoreElements())
        {
            curveNames.add((String) names.nextElement());
        }

        names = NISTNamedCurves.getNames();
        while(names.hasMoreElements())
        {
            curveNames.add((String) names.nextElement());
        }

        return curveNames;
    }

}
