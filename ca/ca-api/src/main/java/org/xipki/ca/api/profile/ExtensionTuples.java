/*
 * Copyright (c) 2014 xipki.org
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

package org.xipki.ca.api.profile;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class ExtensionTuples
{
    private String warning;
    private List<ExtensionTuple> extensions = new LinkedList<>();

    public void addExtension(ExtensionTuple extension)
    {
        if(extension != null)
        {
            extensions.add(extension);
        }
    }

    public List<ExtensionTuple> getExtensions()
    {
        return Collections.unmodifiableList(extensions);
    }

    public void setWarning(String warning)
    {
        this.warning = warning;
    }

    public String getWarning()
    {
        return warning;
    }

}
