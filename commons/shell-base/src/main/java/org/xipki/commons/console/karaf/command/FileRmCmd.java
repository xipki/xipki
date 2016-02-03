/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.console.karaf.command;

import java.io.File;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.commons.console.karaf.XipkiCommandSupport;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.commons.console.karaf.intern.FileUtils;

/**
 * @author Lijun Liao
 * @since 2.0
 */

@Command(scope = "xipki-cmd", name = "rm",
    description = "remove file or directory")
@Service
public class FileRmCmd extends XipkiCommandSupport {

  @Argument(index = 0, name = "file",
      required = true,
      description = "file or directory to be deleted\n"
          + "(required)")
  @Completion(FilePathCompleter.class)
  private String targetPath;

  @Option(name = "--recursive", aliases = "-r",
      description = "remove directories and their contents recursively")
  private Boolean recursive = Boolean.FALSE;

  @Option(name = "--force", aliases = "-f",
      description = "ignore nonexistent files, never prompt")
  private Boolean force = Boolean.FALSE;

  @Override
  protected Object doExecute()
  throws Exception {
    File target = new File(expandFilepath(targetPath));
    if (!target.exists()) {
      return null;
    }

    if (target.isDirectory()) {
      if (!recursive) {
        out("Please use option--recursive to delete directory");
        return null;
      }

      if (force || confirm(
          "Do you want to remove directory " + targetPath + " [yes/no]?", 3)) {
        FileUtils.deleteDirectory(target);
        out("removed directory " + targetPath);
      }
    } else {
      if (force || confirm(
          "Do you want o remove file " + targetPath + " [yes/no]?", 3)) {
        target.delete();
        out("removed file " + targetPath);
      }
    }

    return null;
  }

}
