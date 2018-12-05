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

package org.xipki.ocsp.mgmt.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.shell.Completers;

/**
 * TODO.
 * @author Lijun Liao
 */

@Command(scope = "ocsp", name = "refresh-token", description = "refresh token for signers")
@Service
public class RefreshTokenAction extends OcspAction {

  @Option(name = "--type", required = true, description = "type of the signer")
  @Completion(Completers.SignerTypeCompleter.class)
  protected String type;

  @Override
  protected Object execute0() throws Exception {
    ocspManager.refreshTokenForSignerType(type);
    println("refreshed token for signer type " + type);
    return null;
  } // method execute0

}
