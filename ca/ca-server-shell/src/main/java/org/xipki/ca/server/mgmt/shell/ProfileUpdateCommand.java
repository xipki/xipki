/*
 * Copyright 2014 xipki.org
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
import org.xipki.security.common.IoCertUtil;

@Command(scope = "ca", name = "profile-update", description="Update certificate profile")
public class ProfileUpdateCommand extends CaCommand
{

    @Option(name = "-name",
                description = "Required. Profile name",
                required = true, multiValued = false)
    protected String            name;

    @Option(name = "-type",
            description = "Profile type",
            required = true)
    protected String            type;

    @Option(name = "-conf",
            description = "Profile configuration or 'NULL'")
    protected String            conf;

    @Option(name = "-confFile",
            description = "Profile configuration file")
    protected String            confFile;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(conf == null && confFile != null)
        {
            conf = new String(IoCertUtil.read(confFile));
        }

        caManager.changeCertProfile(name, type, conf);

        return null;
    }
}
