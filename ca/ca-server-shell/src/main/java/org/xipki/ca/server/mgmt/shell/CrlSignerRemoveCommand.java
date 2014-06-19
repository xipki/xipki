/*
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "crlsigner-rm", description="Remove CRL signer")
public class CrlSignerRemoveCommand extends CaCommand
{

    @Option(name = "-name",
            description = "Required. CRL signer name",
            required = true, multiValued = false)
    protected String            name;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.removeCrlSigner(name);
        return null;
    }
}
