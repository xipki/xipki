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

package org.xipki.ca.client.shell;

import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.xipki.ca.client.api.RAWorker;

/**
 * @author Lijun Liao
 */

public abstract class ClientCommand extends OsgiCommandSupport
{
    protected RAWorker            raWorker;

    public final void setRaWorker(RAWorker raWorker)
    {
        this.raWorker = raWorker;
    }

}
