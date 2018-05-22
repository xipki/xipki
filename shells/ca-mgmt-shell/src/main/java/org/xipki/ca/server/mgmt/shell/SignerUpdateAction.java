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

package org.xipki.ca.server.mgmt.shell;

import java.io.ByteArrayInputStream;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.server.mgmt.api.CaManager;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.ca.server.mgmt.api.SignerEntry;
import org.xipki.ca.server.mgmt.shell.completer.SignerNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.SignerTypeCompleter;
import org.xipki.common.util.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.password.PasswordResolver;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "signer-up", description = "update signer")
@Service
public class SignerUpdateAction extends CaAction {

  @Reference
  protected PasswordResolver passwordResolver;

  @Option(name = "--name", aliases = "-n", required = true, description = "signer name")
  @Completion(SignerNameCompleter.class)
  protected String name;

  @Option(name = "--type", description = "type of the signer")
  @Completion(SignerTypeCompleter.class)
  protected String type;

  @Option(name = "--cert", description = "certificate file or 'null'")
  @Completion(FileCompleter.class)
  protected String certFile;

  @Option(name = "--conf", description = "conf of the signer or 'null'")
  private String conf;

  protected String getSignerConf() throws Exception {
    if (conf == null) {
      return null;
    }
    String tmpType = type;
    if (tmpType == null) {
      SignerEntry entry = caManager.getSigner(name);
      if (entry == null) {
        throw new IllegalCmdParamException("please specify the type");
      }
      tmpType = entry.getType();
    }

    return ShellUtil.canonicalizeSignerConf(tmpType, conf, passwordResolver, securityFactory);
  }

  @Override
  protected Object execute0() throws Exception {
    String cert = null;
    if (CaManager.NULL.equalsIgnoreCase(certFile)) {
      cert = CaManager.NULL;
    } else if (certFile != null) {
      byte[] certBytes = IoUtil.read(certFile);
      X509Util.parseCert(new ByteArrayInputStream(certBytes));
      cert = Base64.encodeToString(certBytes);
    }

    String msg = "signer " + name;
    try {
      caManager.changeSigner(name, type, getSignerConf(), cert);
      println("updated " + msg);
      return null;
    } catch (CaMgmtException ex) {
      throw new CmdFailure("could not update " + msg + ", error: " + ex.getMessage(), ex);
    }
  }

}
