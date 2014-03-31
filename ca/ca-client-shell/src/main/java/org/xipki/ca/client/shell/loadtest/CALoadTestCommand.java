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

package org.xipki.ca.client.shell.loadtest;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.xipki.ca.client.api.RAWorker;

@Command(scope = "caclient", name = "enroll-loadtest", description="CA Client Enroll Load test")
public class CALoadTestCommand extends OsgiCommandSupport {

	@Option(name = "-profile",
			required = true, 
			description = "Required. Certificate profile")
    protected String           certProfile;

	@Option(name = "-cn",
			required = true, 
			description = "Required. Common name prefix")
	protected String           commonNamePrefix;

	@Option(name = "-subject",
			required = true, 
			description = "Required. Subject without common name")
	protected String           subjectNoCN;

	@Option(name = "-d",
			required = true, 
			description = "Required. Duration in seconds")
    protected int              durationInSecond;

	@Option(name = "-thread",
			required = false, 
			description = "Number of threads, the default is 5")
    protected Integer          numThreads;

    private RAWorker   		  raWorker;
    	
	@Override
	protected Object doExecute() throws Exception {
		if(numThreads == null)
		{
			numThreads = 5;
		}

		if(numThreads < 1)
		{
			System.err.println("Invalid number of threads " + numThreads);
			return null;
		}

		StringBuilder startMsg = new StringBuilder();
		
		startMsg.append("Threads:      " + numThreads).append("\n");
		startMsg.append("Duration:     " + durationInSecond + " s").append("\n");
		startMsg.append("Subject:      " + "CN=" + commonNamePrefix + "<n>," + subjectNoCN).append("\n");
		startMsg.append("Profile:      " + certProfile).append("\n");
		System.out.print(startMsg.toString());
		
		CALoadTest loadTest = new CALoadTest(raWorker, certProfile, commonNamePrefix, subjectNoCN);
		loadTest.setDuration(durationInSecond);
		loadTest.setThreads(numThreads);
		loadTest.test();
		
		return null;
	}
	
	public void setRaWorker(RAWorker raWorker) {
		this.raWorker = raWorker;
	}
}
