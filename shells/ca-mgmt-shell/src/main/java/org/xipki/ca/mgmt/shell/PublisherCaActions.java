// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.shell;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
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
 * Actions to manage publishers.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class PublisherCaActions {

  @Command(scope = "ca", name = "capub-add", description = "add publisher to CA")
  @Service
  public static class CapubAdd extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--publisher", required = true, multiValued = true, description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private List<String> publisherNames;

    @Override
    protected Object execute0() throws Exception {
      for (String publisherName : publisherNames) {
        String msg = "publisher " + publisherName + " to CA " + caName;
        try {
          caManager.addPublisherToCa(publisherName, caName);
          println("added " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
        }
      }

      return null;
    } // method execute0

  } // class CapubAdd

  @Command(scope = "ca", name = "capub-info", description = "show information of publisher in given CA")
  @Service
  public static class CapubInfo extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Override
    protected Object execute0() throws Exception {
      if (caManager.getCa(caName) == null) {
        throw new CmdFailure("could not find CA '" + caName + "'");
      }

      List<PublisherEntry> entries = caManager.getPublishersForCa(caName);
      if (isNotEmpty(entries)) {
        StringBuilder sb = new StringBuilder().append("publishers for CA ").append(caName).append("\n");
        for (PublisherEntry entry : entries) {
          sb.append("\t").append(entry.getIdent().getName()).append("\n");
        }
        println(sb.toString());
      } else {
        println(StringUtil.concat("no publisher for CA ", caName," is configured"));
      }

      return null;
    } // method execute0

  } // class CapubInfo

  @Command(scope = "ca", name = "capub-rm", description = "remove publisher from CA")
  @Service
  public static class CapubRm extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--publisher", required = true, multiValued = true, description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private List<String> publisherNames;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      for (String publisherName : publisherNames) {
        String msg = "publisher " + publisherName + " from CA " + caName;
        if (force || confirm("Do you want to remove " + msg, 3)) {
          try {
            caManager.removePublisherFromCa(publisherName, caName);
            println("removed " + msg);
          } catch (CaMgmtException ex) {
            throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
          }
        }
      }

      return null;
    } // method execute0

  } // class CapubRm

  @Command(scope = "ca", name = "publisher-add", description = "add publisher")
  @Service
  public static class PublisherAdd extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "publisher Name")
    private String name;

    @Option(name = "--type", required = true, description = "publisher type")
    @Completion(CaCompleters.PublisherTypeCompleter.class)
    private String type;

    @Option(name = "--conf", description = "publisher configuration")
    private String conf;

    @Option(name = "--conf-file", description = "publisher configuration file")
    @Completion(FileCompleter.class)
    private String confFile;

    @Override
    protected Object execute0() throws Exception {
      if (conf == null && confFile != null) {
        conf = StringUtil.toUtf8String(IoUtil.read(confFile));
      }

      String msg = "publisher " + name;
      try {
        caManager.addPublisher(new PublisherEntry(new NameId(null, name), type, conf));
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class PublisherAdd

  @Command(scope = "ca", name = "publisher-export", description = "export publisher configuration")
  @Service
  public static class PublisherExport extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private String name;

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the publisher configuration")
    @Completion(FileCompleter.class)
    private String confFile;

    @Override
    protected Object execute0() throws Exception {
      PublisherEntry entry = caManager.getPublisher(name);
      if (entry == null) {
        throw new IllegalCmdParamException("no publisher named " + name + " is defined");
      }

      if (StringUtil.isBlank(entry.getConf())) {
        println("publisher does not have conf");
      } else {
        saveVerbose("saved publisher configuration to", confFile, StringUtil.toUtf8Bytes(entry.getConf()));
      }
      return null;
    } // method execute0

  } // class PublisherExport

  @Command(scope = "ca", name = "publisher-info", description = "show information of publisher")
  @Service
  public static class PublisherInfo extends CaAction {

    @Argument(index = 0, name = "name", description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private String name;

    @Override
    protected Object execute0() throws Exception {
      if (name == null) {
        Set<String> names = caManager.getPublisherNames();
        int size = names.size();

        StringBuilder sb = new StringBuilder();
        if (size == 0 || size == 1) {
          sb.append((size == 0) ? "no" : "1").append(" publisher is configured\n");
        } else {
          sb.append(size).append(" publishers are configured:\n");
        }

        List<String> sorted = new ArrayList<>(names);
        Collections.sort(sorted);

        for (String entry : sorted) {
          sb.append("\t").append(entry).append("\n");
        }
        println(sb.toString());
      } else {
        PublisherEntry entry = caManager.getPublisher(name);
        if (entry == null) {
          throw new CmdFailure("\tno publisher named '" + name + "' is configured");
        } else {
          println(entry.toString());
        }
      }

      return null;
    } // method execute0

  } // class PublisherInfo

  @Command(scope = "ca", name = "publisher-rm", description = "remove publisher")
  @Service
  public static class PublisherRm extends CaAction {

    @Argument(index = 0, name = "name", required = true, description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private String name;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      String msg = "publisher " + name;
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removePublisher(name);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    } // method execute0

  } // class PublisherRm

  @Command(scope = "ca", name = "publisher-up", description = "update publisher")
  @Service
  public static class PublisherUp extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    protected String name;

    @Option(name = "--type", description = "publisher type")
    @Completion(CaCompleters.PublisherTypeCompleter.class)
    protected String type;

    @Option(name = "--conf", description = "publisher configuration or 'null'")
    protected String conf;

    @Option(name = "--conf-file", description = "profile configuration file")
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

      String msg = "publisher " + name;
      try {
        caManager.changePublisher(name, type, conf);
        println("updated " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not update " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class PublisherUp

}
