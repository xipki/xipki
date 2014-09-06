/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell.completer;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Lijun Liao
 */

public class RcaNameCompleter extends MgmtNameCompleter
{

    @Override
    protected Set<String> getEnums()
    {
        Set<String> ret = new HashSet<>();
        for(String name : caManager.getCaNames())
        {
            X509Certificate cert = caManager.getCA(name).getCertificate();
            if(cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal()))
            {
                ret.add(name);
            }
        }
        return ret;
    }

}
