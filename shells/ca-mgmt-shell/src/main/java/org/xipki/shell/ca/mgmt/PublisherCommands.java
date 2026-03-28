// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.ca.mgmt;

import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.shell.Completion;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.misc.StringUtil;
import picocli.CommandLine;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Actions to manage publishers.
 *
 * @author Lijun Liao (xipki)
 */
public class PublisherCommands {
  @CommandLine.Command(name = "capub-add", description = "add publisher to CA",
      mixinStandardHelpOptions = true)
  public static class CapubAddCommand extends CaMgmtUtil.CaMgmtCommand {

    @CommandLine.Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @CommandLine.Option(names = "--publisher", required = true, description = "publisher names")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private List<String> publisherNames;

    @Override
    public void run() {
      try {
        for (String publisherName : publisherNames) {
          client().addPublisherToCa(publisherName, caName);
          println("added publisher " + publisherName + " to CA " + caName);
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not add publisher to CA: " + ex.getMessage(), ex);
      }
    }
  }

  @CommandLine.Command(name = "capub-info",
      description = "show information of publisher in given CA", mixinStandardHelpOptions = true)
  static class CapubInfoCommand extends CaMgmtUtil.CaMgmtCommand {

    @CommandLine.Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Override
    public void run() {
      try {
        Set<String> publisherNames = client().getPublisherNamesForCa(caName);
        if (CollectionUtil.isEmpty(publisherNames)) {
          println("no publisher for CA " + caName + " is configured");
          return;
        }

        List<String> sorted = new ArrayList<>(publisherNames);
        Collections.sort(sorted);
        StringBuilder sb = new StringBuilder("publishers for CA ").append(caName).append('\n');
        for (String name : sorted) {
          sb.append('\t').append(name).append('\n');
        }
        println(sb.toString());
      } catch (Exception ex) {
        throw new RuntimeException("could not get publishers for CA: " + ex.getMessage(), ex);
      }
    }
  }

  @CommandLine.Command(name = "capub-rm", description = "remove publisher from CA",
      mixinStandardHelpOptions = true)
  public static class CapubRmCommand extends CaMgmtUtil.CaMgmtCommand {

    @CommandLine.Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @CommandLine.Option(names = "--publisher", required = true, description = "publisher names")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private List<String> publisherNames;

    @CommandLine.Option(names = {"--force", "-f"}, description = "without prompt")
    private boolean force;

    @Override
    public void run() {
      try {
        for (String publisherName : publisherNames) {
          if (force || confirmAction("Do you want to remove publisher " + publisherName
              + " from CA " + caName)) {
            client().removePublisherFromCa(publisherName, caName);
            println("removed publisher " + publisherName + " from CA " + caName);
          }
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not remove publisher from CA: " + ex.getMessage(), ex);
      }
    }
  }

  @CommandLine.Command(name = "publisher-add", description = "add publisher",
      mixinStandardHelpOptions = true)
  public static class PublisherAddCommand extends CaMgmtUtil.CaMgmtCommand {

    @CommandLine.Option(names = {"--name", "-n"}, required = true, description = "publisher name")
    private String name;

    @CommandLine.Option(names = "--type", required = true, description = "publisher type")
    @Completion(CaCompleters.PublisherTypeCompleter.class)
    private String type;

    @CommandLine.Option(names = "--conf", description = "publisher configuration")
    private String conf;

    @CommandLine.Option(names = "--conf-file", description = "publisher configuration file")
    @Completion(FilePathCompleter.class)
    private String confFile;

    @Override
    public void run() {
      try {
        String effectiveConf = CaMgmtUtil.loadOptionalText(conf, confFile);
        client().addPublisher(new PublisherEntry(new NameId(null, name), type, effectiveConf));
        println("added publisher " + name);
      } catch (Exception ex) {
        throw new RuntimeException("could not add publisher " + name + ": " + ex.getMessage(), ex);
      }
    }
  }

  @CommandLine.Command(name = "publisher-export", description = "export publisher configuration",
      mixinStandardHelpOptions = true)
  static class PublisherExportCommand extends CaMgmtUtil.CaMgmtCommand {

    @CommandLine.Option(names = {"--name", "-n"}, required = true, description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private String name;

    @CommandLine.Option(names = {"--out", "-o"}, required = true, description = "output file")
    @Completion(FilePathCompleter.class)
    private String confFile;

    @Override
    public void run() {
      try {
        PublisherEntry entry = Optional.ofNullable(client().getPublisher(name))
            .orElseThrow(() -> new CaMgmtException("no publisher named " + name + " is defined"));
        if (StringUtil.isBlank(entry.conf())) {
          println("publisher does not have conf");
        } else {
          saveVerbose("saved publisher configuration to", confFile,
              StringUtil.toUtf8Bytes(entry.conf()));
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not export publisher configuration: "
            + ex.getMessage(), ex);
      }
    }
  }

  @CommandLine.Command(name = "publisher-info", description = "show information of publisher",
      mixinStandardHelpOptions = true)
  static class PublisherInfoCommand extends CaMgmtUtil.CaMgmtCommand {

    @CommandLine.Parameters(index = "0", arity = "0..1", description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private String name;

    @Override
    public void run() {
      try {
        if (name == null) {
          println(CaMgmtUtil.formatNames("publisher", client().getPublisherNames()));
          return;
        }

        PublisherEntry entry = Optional.ofNullable(client().getPublisher(name)).orElseThrow(() ->
            new CaMgmtException("no publisher named '" + name + "' is configured"));
        println(entry.toString());
      } catch (Exception ex) {
        throw new RuntimeException("could not get publisher info: " + ex.getMessage(), ex);
      }
    }
  }

  @CommandLine.Command(name = "publisher-rm", description = "remove publisher",
      mixinStandardHelpOptions = true)
  public static class PublisherRmCommand extends CaMgmtUtil.CaMgmtCommand {

    @CommandLine.Parameters(index = "0", description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private String name;

    @CommandLine.Option(names = {"--force", "-f"}, description = "without prompt")
    private boolean force;

    @Override
    public void run() {
      try {
        if (force || confirmAction("Do you want to remove publisher " + name)) {
          client().removePublisher(name);
          println("removed publisher " + name);
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not remove publisher " + name + ": "
            + ex.getMessage(), ex);
      }
    }
  }

  @CommandLine.Command(name = "publisher-up", description = "update publisher",
      mixinStandardHelpOptions = true)
  public static class PublisherUpCommand extends CaMgmtUtil.CaMgmtCommand {

    @CommandLine.Option(names = {"--name", "-n"}, required = true, description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private String name;

    @CommandLine.Option(names = "--type", description = "publisher type")
    @Completion(CaCompleters.PublisherTypeCompleter.class)
    private String type;

    @CommandLine.Option(names = "--conf", description = "publisher configuration or null")
    private String conf;

    @CommandLine.Option(names = "--conf-file", description = "publisher configuration file")
    @Completion(FilePathCompleter.class)
    private String confFile;

    @Override
    public void run() {
      try {
        if (type == null && conf == null && confFile == null) {
          throw new IllegalArgumentException("nothing to update");
        }
        String effectiveConf = CaMgmtUtil.loadOptionalText(conf, confFile);
        client().changePublisher(name, type, effectiveConf);
        println("updated publisher " + name);
      } catch (Exception ex) {
        throw new RuntimeException("could not update publisher " + name + ": "
            + ex.getMessage(), ex);
      }
    }
  }
}
