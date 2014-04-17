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

package org.xipki.ocsp;

import java.util.HashMap;
import java.util.Map;

public class CertprofileStore
{
    private final Map<String, Integer> nameIdMap;
    private final Map<Integer, String> idNameMap;

    public CertprofileStore(Map<Integer, String> entries)
    {
        this.nameIdMap = new HashMap<String, Integer>();
        this.idNameMap = new HashMap<Integer, String>();

        for(Integer id : entries.keySet())
        {
            String name = entries.get(id);

            if(idNameMap.containsKey(id))
            {
                throw new IllegalArgumentException("certprofile with the same id " + id + " already available");
            }

            if(nameIdMap.containsKey(name))
            {
                throw new IllegalArgumentException("certprofile with the same name " + name + " already available");
            }

            this.idNameMap.put(id, name);
            this.nameIdMap.put(name, id);
        }
    }

    public Integer getId(String name)
    {
        return nameIdMap.get(name);
    }

    public String getName(int id)
    {
        return idNameMap.get(id);
    }

}
