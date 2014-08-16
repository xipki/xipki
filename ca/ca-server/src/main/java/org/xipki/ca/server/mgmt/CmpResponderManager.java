/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt;

import org.xipki.ca.server.X509CACmpResponder;

/**
 * @author Lijun Liao
 */

public interface CmpResponderManager
{
    String getCaName(String caAlias);

    X509CACmpResponder getX509CACmpResponder(String caName);
}
