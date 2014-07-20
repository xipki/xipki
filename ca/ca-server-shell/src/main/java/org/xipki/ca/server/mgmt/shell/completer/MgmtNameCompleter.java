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

package org.xipki.ca.server.mgmt.shell.completer;

import org.xipki.ca.server.mgmt.CAManager;
import org.xipki.console.karaf.DynamicEnumCompleter;

/**
 * @author Lijun Liao
 */

public abstract class MgmtNameCompleter extends DynamicEnumCompleter
{
    protected CAManager caManager;

    public void setCaManager(CAManager caManager)
    {
        this.caManager = caManager;
    }

}
