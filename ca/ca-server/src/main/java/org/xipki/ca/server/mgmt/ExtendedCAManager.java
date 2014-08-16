/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt;

import org.xipki.ca.server.X509CA;
import org.xipki.ca.server.X509CACmpResponder;
import org.xipki.ca.server.mgmt.api.CAManager;

/**
 * @author Lijun Liao
 */

public interface ExtendedCAManager extends CAManager
{
    X509CA getX509CA(String caName);

    X509CACmpResponder getX509CACmpResponder(String caName);

}
