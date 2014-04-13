/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.dbi.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.dbi.OcspDbImporter;
import org.xipki.security.api.PasswordResolver;

@Command(scope = "dbtool", name = "import-ocsp", description="Import OCSP database")
public class ImportOcspCommand extends OsgiCommandSupport {	
	@Option(name = "-dbconf",
	        description = "Required. Database configuration file",
	        required = true)
	protected String            dbconfFile;
	
	@Option(name = "-indir",
	        description = "Required. Input directory",
	        required = true)
	protected String            indir;
	
	private DataSourceFactory dataSourceFactory;
	private PasswordResolver passwordResolver;
	
	@Override
	protected Object doExecute() throws Exception {
		OcspDbImporter importer = new OcspDbImporter(dataSourceFactory, passwordResolver, dbconfFile);
		importer.importDatabase(indir);
		return null;
    }

	public void setDataSourceFactory(DataSourceFactory dataSourceFactory) {
		this.dataSourceFactory = dataSourceFactory;
	}

	public void setPasswordResolver(PasswordResolver passwordResolver) {
		this.passwordResolver = passwordResolver;
	}
}
