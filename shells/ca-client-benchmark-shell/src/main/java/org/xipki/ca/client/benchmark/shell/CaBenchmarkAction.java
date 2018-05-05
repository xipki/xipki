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

package org.xipki.ca.client.benchmark.shell;

import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.xipki.ca.client.api.CaClient;
import org.xipki.console.karaf.XiAction;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class CaBenchmarkAction extends XiAction {

  @Reference
  protected CaClient caClient;

}
