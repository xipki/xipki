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

import java.util.List;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "clear-publishqueue", description="Clear publish queue")
public class ClearPublishQueueCommand extends CaCommand
{
    @Option(name = "-ca",
            description = "Required. CA name or 'all' for all CAs",
            required = true)
    protected String           caName;

    @Option(name = "-publisher",
        required = true, multiValued = true,
        description = "Required. Publisher name or 'all' for all publishers. Multivalued")
    protected List<String>     publisherNames;

    @Override
    protected Object doExecute()
    throws Exception
    {
        boolean allPublishers = false;
        for(String publisherName : publisherNames)
        {
            if("all".equalsIgnoreCase(publisherName))
            {
                allPublishers = true;
                break;
            }
        }

        if(allPublishers)
        {
            publisherNames = null;
        }

        if("all".equalsIgnoreCase(caName))
        {
            caName = null;
        }

        caManager.clearPublishQueue(caName, publisherNames);
        return null;
    }
}
