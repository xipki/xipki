/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell;

import org.apache.felix.gogo.commands.Option;

/**
 * @author Lijun Liao
 */

public abstract class RAUnRevRemoveCertCommand extends ClientCommand
{
    @Option(name = "-cert",
            description = "Certificate file")
    protected String            certFile;

    @Option(name = "-cacert",
            description = "CA Certificate file")
    protected String            caCertFile;

    @Option(name = "-serial",
            description = "Serial number")
    protected String            serialNumber;

}
