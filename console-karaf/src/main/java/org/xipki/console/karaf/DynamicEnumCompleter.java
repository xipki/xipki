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

package org.xipki.console.karaf;

import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.console.Completer;
import org.apache.karaf.shell.console.completer.StringsCompleter;

/**
 * @author Lijun Liao
 */

public abstract class DynamicEnumCompleter implements Completer
{
    protected abstract Set<String> getEnums();

    @Override
    public int complete(String buffer, int cursor, List<String> candidates)
    {
        StringsCompleter delegate = new StringsCompleter();

        for(String s : getEnums())
        {
            delegate.getStrings().add(s);
        }

        return delegate.complete(buffer, cursor, candidates);
    }

}
