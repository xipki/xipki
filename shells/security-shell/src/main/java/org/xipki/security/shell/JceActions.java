// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

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
 * Actions for JCE device.
 *
 * @author Lijun Liao (xipki)
 */

public class JceActions {

  @Command(scope = "xi", name = "csr-jce", description = "generate CSR request with JCE device")
  @Service
  public static class CsrJce extends SecurityActions.BaseCsrGenAction {

    @Option(name = "--type", required = true, description = "JCE signer type")
    private String type;

    @Option(name = "--alias", required = true, description = "alias of the key in the JCE device")
    private String alias;

    @Option(name = "--algo", required = true, description = "signature algorithm")
    @Completion(SecurityCompleters.SignAlgoCompleter.class)
    private String algo;

    @Override
    protected ConcurrentContentSigner getSigner() throws Exception {
      SignerConf conf = getJceSignerConf(alias, 1, SignAlgo.getInstance(algo));
      return securityFactory.createSigner(type, conf, (X509Cert[]) null);
    }

    private static SignerConf getJceSignerConf(String alias, int parallelism, SignAlgo signAlgo) {
      ConfPairs conf = new ConfPairs()
          .putPair("parallelism", Integer.toString(parallelism))
          .putPair("alias", alias)
          .putPair("algo", signAlgo.getJceName());
      return new SignerConf(conf);
    } // method getJceSignerConf

  } // class CsrP11

}
