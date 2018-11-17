/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.client.shell;

import java.util.Collections;
import java.util.Set;

import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.casdk.cmp.CmpCaSdk;
import org.xipki.casdk.cmp.CmpCaSdkException;
import org.xipki.shell.completer.AbstractDynamicEnumCompleter;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Service
public class CaNameCompleter extends AbstractDynamicEnumCompleter {

  @Reference
  protected CmpCaSdk caSdk;

  @Override
  protected Set<String> getEnums() {
    try {
      return caSdk.getCaNames();
    } catch (CmpCaSdkException ex) {
      return Collections.emptySet();
    }
  }

}
