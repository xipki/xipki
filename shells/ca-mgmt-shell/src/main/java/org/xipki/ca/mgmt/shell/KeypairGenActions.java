// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.shell;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.KeypairGenEntry;
import org.xipki.ca.mgmt.shell.CaActions.CaAction;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Actions to manage Keypair generation entries.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */
public class KeypairGenActions {

  @Command(scope = "ca", name = "keypairgen-add", description = "add keypair generation")
  @Service
  public static class KeypairGenAdd extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "keypair generation name")
    @Completion(CaCompleters.KeypairGenNameCompleter.class)
    private String name;

    @Option(name = "--type", required = true, description = "keypair generation type")
    @Completion(CaCompleters.KeypairGenTypeCompleter.class)
    private String type;

    @Option(name = "--conf", description = "keypair generation configuration")
    private String conf;

    @Option(name = "--conf-file", description = "keypair generation configuration file")
    @Completion(FileCompleter.class)
    private String confFile;

    @Override
    protected Object execute0() throws Exception {
      if (conf == null && confFile != null) {
        conf = StringUtil.toUtf8String(IoUtil.read(confFile));
      }

      KeypairGenEntry entry = new KeypairGenEntry(name, type, conf);
      String msg = "keypair generation " + name;
      try {
        caManager.addKeypairGen(entry);
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class KeypairGenActions

  @Command(scope = "ca", name = "keypairgen-info", description = "show information of keypair generation")
  @Service
  public static class KeypairGenInfo extends CaAction {

    @Argument(index = 0, name = "name", description = "keypair generation name")
    @Completion(CaCompleters.KeypairGenNameCompleter.class)
    private String name;

    @Override
    protected Object execute0() throws Exception {
      if (name == null) {
        Set<String> names = caManager.getKeypairGenNames();
        int size = names.size();

        StringBuilder sb = new StringBuilder();
        if (size == 0 || size == 1) {
          sb.append((size == 0) ? "no" : "1").append(" keypair generation is configured\n");
        } else {
          sb.append(size).append(" keypair generation entries are configured:\n");
        }

        List<String> sorted = new ArrayList<>(names);
        Collections.sort(sorted);

        for (String entry : sorted) {
          sb.append("\t").append(entry).append("\n");
        }
        println(sb.toString());
      } else {
        KeypairGenEntry entry = caManager.getKeypairGen(name);
        if (entry == null) {
          throw new CmdFailure("\tno keypair generation named '" + name + "' is configured");
        } else {
          println(entry.toString());
        }
      }

      return null;
    } // method execute0

  } // class KeypairGenInfo

  @Command(scope = "ca", name = "keypairgen-rm", description = "remove keypair generation")
  @Service
  public static class KeypairGenRm extends CaAction {

    @Argument(index = 0, name = "name", required = true, description = "keypair generation name")
    @Completion(CaCompleters.KeypairGenNameCompleter.class)
    private String name;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      String msg = "keypair generation " + name;
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removeKeypairGen(name);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    } // method execute0

  } // class KeypairGenRm

  @Command(scope = "ca", name = "keypairgen-up", description = "update keypair generation")
  @Service
  public static class KeypairGenUp extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "keypair generation name")
    @Completion(CaCompleters.KeypairGenNameCompleter.class)
    protected String name;

    @Option(name = "--type", description = "keypair generation type")
    @Completion(CaCompleters.KeypairGenTypeCompleter.class)
    protected String type;

    @Option(name = "--conf", description = "keypair generation configuration or 'null'")
    protected String conf;

    @Option(name = "--conf-file", description = "keypair generation configuration file")
    @Completion(FileCompleter.class)
    protected String confFile;

    @Override
    protected Object execute0() throws Exception {
      if (type == null && conf == null && confFile == null) {
        throw new IllegalCmdParamException("nothing to update");
      }

      if (conf == null && confFile != null) {
        conf = StringUtil.toUtf8String(IoUtil.read(confFile));
      }

      String msg = "keypair generation " + name;
      try {
        caManager.changeKeypairGen(name, type, conf);
        println("updated " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not update " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class KeypairGenUp

}
