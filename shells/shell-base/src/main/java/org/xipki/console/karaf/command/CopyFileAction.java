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

package org.xipki.console.karaf.command;

import java.io.File;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.console.karaf.FileUtils;
import org.xipki.console.karaf.XiAction;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "copy-file", description = "copy file")
@Service
public class CopyFileAction extends XiAction {

  @Argument(index = 0, name = "source file", required = true,
      description = "file to be copied\n(required)")
  @Completion(FileCompleter.class)
  private String source;

  @Argument(index = 1, name = "destination", required = true,
      description = "destination directory or file\n(required)")
  @Completion(FileCompleter.class)
  private String dest;

  @Option(name = "--force", aliases = "-f", description = "override existing file, never prompt")
  private Boolean force = Boolean.FALSE;

  @Override
  protected Object execute0() throws Exception {
    File sourceFile = new File(expandFilepath(source));
    if (!sourceFile.exists()) {
      System.err.println(source + " does not exist");
      return null;
    }

    if (!sourceFile.isFile()) {
      System.err.println(source + " is not a file");
      return null;
    }

    File destFile = new File(dest);
    if (destFile.exists()) {
      if (!destFile.isFile()) {
        System.err.println("cannot override an existing directory by a file");
        return null;
      } else {
        if (!force.booleanValue() && !confirm("Do you want to override the file " + dest, 3)) {
          return null;
        }
      }
    } else {
      File parent = destFile.getParentFile();
      if (parent != null) {
        parent.mkdirs();
      }
    }

    FileUtils.copyFile(sourceFile, destFile, true);

    return null;
  }

}
