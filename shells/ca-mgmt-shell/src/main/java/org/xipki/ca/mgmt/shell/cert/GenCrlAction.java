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

package org.xipki.ca.mgmt.shell.cert;

import java.security.cert.X509CRL;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "gencrl", description = "generate CRL")
@Service
public class GenCrlAction extends CrlAction {

  @Option(name = "--out", aliases = "-o", description = "where to save the CRL")
  @Completion(FileCompleter.class)
  protected String outFile;

  @Override
  protected X509CRL retrieveCrl() throws Exception {
    return caManager.generateCrlOnDemand(caName);
  }

  @Override
  protected String getOutFile() {
    return outFile;
  }

}
