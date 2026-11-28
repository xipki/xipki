// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.test;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.xipki.ca.api.profile.CertprofileValidator;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.conf.XijsonCertprofileType;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Every certificate profile shipped in the setup and QA assemblies can be parsed,
 * initialized and passes the {@link CertprofileValidator}.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Parameterized.class)
public class ShippedProfilesTest {

  private static final String[] DIRS = {
      "../assemblies/xipki-setup/src/assembly/unfiltered/xipki-mgmt-cli/xipki/ca-setup/certprofile",
      "../assemblies/xipki-qa/src/assembly/unfiltered/xipki-qa-cli/qa/certprofile",
      "../assemblies/xipki-qa/src/assembly/unfiltered/xipki-qa-cli/qa/cab/certprofile"};

  private final Path file;

  public ShippedProfilesTest(String name, Path file) {
    this.file = file;
  }

  @Parameterized.Parameters(name = "{0}")
  public static List<Object[]> profiles() throws IOException {
    List<Object[]> ret = new ArrayList<>();
    for (String dir : DIRS) {
      Path path = Paths.get(dir);
      Assert.assertTrue("directory " + path.toAbsolutePath() + " exists", Files.isDirectory(path));
      try (Stream<Path> files = Files.list(path)) {
        files.filter(f -> f.getFileName().toString().matches("certprofile-.*\\.json"))
            .sorted()
            .forEach(f -> ret.add(new Object[]{
                path.getParent().getFileName() + "/" + f.getFileName(), f}));
      }
    }
    return ret;
  }

  /** Profile with an own extension, loaded with {@link ExtendedCertprofile}. */
  private static final String EXTENDED = "certprofile-extended.json";

  @Test
  public void profileIsValid() throws Exception {
    XijsonCertprofileType conf = XijsonCertprofileType.parse(file.toFile());
    XijsonCertprofile profile = EXTENDED.equals(file.getFileName().toString())
        ? new ExtendedCertprofile() : new XijsonCertprofile();
    profile.initialize(conf);
    CertprofileValidator.validate(profile);
  }

}
