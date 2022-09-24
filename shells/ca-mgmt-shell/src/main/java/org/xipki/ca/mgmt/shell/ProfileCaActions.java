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

package org.xipki.ca.mgmt.shell;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.mgmt.shell.CaActions.CaAction;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.CollectionUtil;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Actions to manage certificate profiles.
 *
 * @author Lijun Liao
 *
 */
public class ProfileCaActions {

  @Command(scope = "ca", name = "caprofile-add", description = "add certificate profile to CA")
  @Service
  public static class CaprofileAdd extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--profile", required = true, multiValued = true, description = "profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private List<String> profileNames;

    @Override
    protected Object execute0() throws Exception {
      for (String profileName : profileNames) {
        String msg = StringUtil.concat("certificate profile ", profileName, " to CA ", caName);
        try {
          caManager.addCertprofileToCa(profileName, caName);
          println("associated " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not associate " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    } // method execute0

  } // class CaprofileAdd

  @Command(scope = "ca", name = "caprofile-info", description = "show information of certificate profile in given CA")
  @Service
  public static class CaprofileInfo extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Override
    protected Object execute0() throws Exception {
      if (caManager.getCa(caName) == null) {
        throw new CmdFailure("could not find CA '" + caName + "'");
      }

      StringBuilder sb = new StringBuilder();
      Set<String> entries = caManager.getCertprofilesForCa(caName);
      if (CollectionUtil.isNotEmpty(entries)) {
        sb.append("certificate Profiles supported by CA ").append(caName).append("\n");

        for (String name: entries) {
          sb.append("\t").append(name).append("\n");
        }
      } else {
        sb.append("\tno profile for CA ").append(caName).append(" is configured");
      }

      println(sb.toString());
      return null;
    } // method execute0

  } // class CaprofileInfo

  @Command(scope = "ca", name = "caprofile-rm", description = "remove certificate profile from CA")
  @Service
  public static class CaprofileRm extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--profile", required = true, multiValued = true, description = "certificate profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private List<String> profileNames;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      for (String profileName : profileNames) {
        String msg = StringUtil.concat("certificate profile ", profileName, " from CA ", caName);
        if (force || confirm("Do you want to remove " + msg, 3)) {
          try {
            caManager.removeCertprofileFromCa(profileName, caName);
            println("removed " + msg);
          } catch (CaMgmtException ex) {
            throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
          }
        }
      }

      return null;
    } // method execute0

  } // class CaprofileRm

  @Command(scope = "ca", name = "profile-add", description = "add certificate profile")
  @Service
  public static class ProfileAdd extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "profile name")
    private String name;

    @Option(name = "--type", description = "profile type")
    @Completion(CaCompleters.ProfileTypeCompleter.class)
    private String type = "xijson";

    @Option(name = "--conf", description = "certificate profile configuration")
    private String conf;

    @Option(name = "--conf-file", description = "certificate profile configuration file")
    @Completion(FileCompleter.class)
    private String confFile;

    @Override
    protected Object execute0() throws Exception {
      if (conf == null && confFile != null) {
        conf = StringUtil.toUtf8String(IoUtil.read(confFile));
      }

      String msg = "certificate profile " + name;
      try {
        caManager.addCertprofile(new CertprofileEntry(new NameId(null, name), type, conf));
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class ProfileAdd

  @Command(scope = "ca", name = "profile-export", description = "export certificate profile configuration")
  @Service
  public static class ProfileExport extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String name;

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the profile configuration")
    @Completion(FileCompleter.class)
    private String confFile;

    @Override
    protected Object execute0() throws Exception {
      CertprofileEntry entry = caManager.getCertprofile(name);
      if (entry == null) {
        throw new IllegalCmdParamException("no certificate profile named " + name + " is defined");
      }

      if (StringUtil.isBlank(entry.getConf())) {
        println("cert profile does not have conf");
      } else {
        saveVerbose("saved cert profile configuration to", confFile,
            StringUtil.toUtf8Bytes(entry.getConf()));
      }
      return null;
    } // method execute0

  } // class ProfileExport

  @Command(scope = "ca", name = "profile-info", description = "show information of certificate profile")
  @Service
  public static class ProfileInfo extends CaAction {

    @Argument(index = 0, name = "name", description = "certificate profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String name;

    @Option(name = "--verbose", aliases = "-v", description = "show certificate profile information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      StringBuilder sb = new StringBuilder();

      if (name == null) {
        Set<String> names = caManager.getCertprofileNames();
        int size = names.size();

        if (size == 0 || size == 1) {
          sb.append((size == 0) ? "no" : "1").append(" profile is configured\n");
        } else {
          sb.append(size).append(" profiles are configured:\n");
        }

        List<String> sorted = new ArrayList<>(names);
        Collections.sort(sorted);

        for (String entry : sorted) {
          sb.append("\t").append(entry).append("\n");
        }
      } else {
        CertprofileEntry entry = caManager.getCertprofile(name);
        if (entry == null) {
          throw new CmdFailure("\tno certificate profile named '" + name + "' is configured");
        } else {
          sb.append(entry.toString(verbose));
        }
      }

      println(sb.toString());
      return null;
    } // method execute0

  } // class ProfileInfo

  @Command(scope = "ca", name = "profile-rm", description = "remove certificate profile")
  @Service
  public static class ProfileRm extends CaAction {

    @Argument(index = 0, name = "name", required = true, description = "certificate profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String name;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      String msg = "certificate profile " + name;
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removeCertprofile(name);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    } // method execute0

  } // class ProfileRm

  @Command(scope = "ca", name = "profile-up", description = "update certificate profile")
  @Service
  public static class ProfileUp extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    protected String name;

    @Option(name = "--type", description = "profile type")
    @Completion(CaCompleters.ProfileTypeCompleter.class)
    protected String type;

    @Option(name = "--conf", description = "certificate profile configuration or 'null'")
    protected String conf;

    @Option(name = "--conf-file", description = "certificate profile configuration file")
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

      String msg = "certificate profile " + name;
      try {
        caManager.changeCertprofile(name, type, conf);
        println("updated " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not update " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class ProfileUp

}
