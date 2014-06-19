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

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "unlock", description="Unlock the CA syste")
public class UnlockCACommand extends CaCommand
{
    @Override
    protected Object doExecute()
    throws Exception
    {
        boolean unlocked = caManager.unlockCA();

        if(unlocked)
        {
            System.out.println("Unlocked CA system, calling ca:ca-restart to restart CA system");
        }
        else
        {
            System.err.println("Could not unlock CA system");
        }

        return null;
    }
}
