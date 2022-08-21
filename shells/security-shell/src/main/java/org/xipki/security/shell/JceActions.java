/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.security.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SignAlgo;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.util.ConfPairs;

/**
 * Actions for PKCS#11 security.
 *
 * @author Lijun Liao
 */

public class JceActions {

  @Command(scope = "xi", name = "csr-jce", description = "generate CSR request with JCE device")
  @Service
  public static class CsrJce extends Actions.BaseCsrGenAction {

    @Option(name = "--type", required = true, description = "JCE signer type")
    private String type;

    @Option(name = "--alias", required = true, description = "alias of the key in the JCE device")
    private String alias;

    @Option(name = "--algo", required = true, description = "signature algorithm")
    @Completion(SecurityCompleters.SignAlgoCompleter.class)
    private String algo;

    @Override
    protected ConcurrentContentSigner getSigner()
        throws Exception {
      SignerConf conf = getJceSignerConf(alias, 1, SignAlgo.getInstance(algo));
      return securityFactory.createSigner(type, conf, (X509Cert[]) null);
    }

    private static SignerConf getJceSignerConf(String alias, int parallelism, SignAlgo signAlgo) {
      ConfPairs conf = new ConfPairs();
      conf.putPair("parallelism", Integer.toString(parallelism));
      conf.putPair("alias", alias);
      conf.putPair("algo", signAlgo.getJceName());
      return new SignerConf(conf.getEncoded());
    } // method getJceSignerConf

  } // class CsrP11

}
