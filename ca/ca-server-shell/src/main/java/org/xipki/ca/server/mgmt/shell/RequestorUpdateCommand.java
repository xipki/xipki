/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.io.ByteArrayInputStream;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.util.encoders.Base64;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "requestor-update", description="Update requestor")
public class RequestorUpdateCommand extends CaCommand
{
    @Option(name = "-name",
            description = "Required. Requestor name",
            required = true)
    protected String name;

    @Option(name = "-cert",
            description = "Required. Requestor certificate file",
            required = true)
    protected String certFile;

    @Override
    protected Object doExecute()
    throws Exception
    {
        // check if the certificate is valid
        byte[] certBytes = IoCertUtil.read(certFile);
        IoCertUtil.parseCert(new ByteArrayInputStream(certBytes));
        caManager.changeCmpRequestor(name, Base64.toBase64String(certBytes));

        return null;
    }
}
