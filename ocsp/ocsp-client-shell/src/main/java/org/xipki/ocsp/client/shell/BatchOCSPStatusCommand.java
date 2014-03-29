/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This work is part of XiPKI, owned by Lijun Liao (lijun.liao@gmail.com)
 *
 */

package org.xipki.ocsp.client.shell;

import java.math.BigInteger;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.xipki.ocsp.client.api.OCSPRequestor;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.security.common.IoCertUtil;

@Command(scope = "ocsp", name = "batch-status", description="Request certificate status")
public class BatchOCSPStatusCommand extends OsgiCommandSupport {
	private static final String DFLT_URL = "http://localhost:8080/ocsp";
	@Option(name = "-url",
			description = "Server URL, the default is " + DFLT_URL)
    protected String            serverURL;

	@Option(name = "-ca",
			required = true, description = "Required. CA certificate file")
    protected String            cacertFile;

	@Option(name = "-ss",
			required = true, 
			description = "Required. Start Serial number")
    protected Long              startSerialNumber;

	@Option(name = "-es",
			required = true, 
			description = "Required. End Serial number")
    protected Long              endSerialNumber;

	@Option(name = "-i",
			required = false, 
			description = "Interval in milli seconds, the default is 100")
    protected Long              intervalInMs;

	private OCSPRequestor	  requestor;
    	
	@Override
	protected Object doExecute() throws Exception {
		if(intervalInMs == null)
		{
			intervalInMs = 100L;
		}
		
		if(startSerialNumber < 1 || endSerialNumber < 1 || startSerialNumber >= endSerialNumber)
		{
			System.err.println("invalid serial number");
			return null;
		}

		if(intervalInMs < 0)
		{
			System.err.println("Invalid interval " + intervalInMs);
			return null;
		}

		URL serverUrl = new URL(serverURL == null ? DFLT_URL : serverURL);
		
		StringBuilder startMsg = new StringBuilder();
		
		startMsg.append("Interval:     " + intervalInMs + " ms").append("\n");
		startMsg.append("Start Serial: " + startSerialNumber).append("\n");
		startMsg.append("End Serial:   " + endSerialNumber).append("\n");
		startMsg.append("CA cert:      " + cacertFile).append("\n");
		startMsg.append("Server URL:   " + serverUrl.toString()).append("\n");
		startMsg.append("Start fime:   " + new Date()).append("\n");
		
		System.out.print(startMsg.toString());
		
		X509Certificate caCert = IoCertUtil.parseCert(cacertFile);
		
		RequestOptions options = new RequestOptions();
		options.setUseNonce(true);	
		options.setHashAlgorithmId(NISTObjectIdentifiers.id_sha256);
		
		long num = 0;
		long errorNum = 0;		
		
		for(long serial = startSerialNumber; serial <= endSerialNumber; serial++)
		{
			try{			
				System.out.println("----- OCSP #=" + (num++) + ", #error=" +
						errorNum + ", SN=" + serial + " --------");
				
				try{
					Thread.sleep(intervalInMs);
				}catch(InterruptedException e)
				{					
				}
				
				BasicOCSPResp basicResp = requestor.ask(caCert, BigInteger.valueOf(serial), serverUrl, options);
	
				SingleResp[] singleResponses = basicResp.getResponses();
				
				int n = singleResponses == null ? 0 : singleResponses.length;
				if(n == 0)
				{
					errorNum++;
					System.out.println("Received no status from server");
				}
				else if(n != 1)
				{
					errorNum++;
					String msg = "Received status with " + n + 
							" single responses from server, but 1 was requested\n";
					System.out.println(msg);
				}
				else
				{
					SingleResp singleResp = singleResponses[0];
					CertificateStatus singleCertStatus = singleResp.getCertStatus();
					
					String status ;
					if(singleCertStatus == null)
					{
						status = "Good";
					}
					else if(singleCertStatus instanceof RevokedStatus)
					{
						int reason = ((RevokedStatus) singleCertStatus).getRevocationReason();
						Date revTime = ((RevokedStatus) singleCertStatus).getRevocationTime();
						status = "Revocated, reason = "+ reason + ", revocationTime = " + revTime;
					}
					else if(singleCertStatus instanceof UnknownStatus)
					{
						status = "Unknown";
					}
					else
					{
						status = "ERROR";
					}
					
					System.out.println("Certificate status: " + status);
					
					Extension certHashExtension = singleResp.getExtension(ISISMTTObjectIdentifiers.id_isismtt_at_certHash);
					if(certHashExtension != null)
					{
						System.out.println("CertHash is provided");
					}
				}
			}catch(Throwable t)
			{
				System.err.println("Error: " + t.getClass().getName() + ": " + t.getMessage());
				errorNum++;
			}
		}
		
		StringBuilder summary = new StringBuilder("----------------------------------------\n");
		summary.append("#OCSP-Status: ").append(num).append("\n");
		summary.append("#ERROR: ").append(errorNum).append("\n");
		summary.append("End Time: ").append(new Date()).append("\n");
		
		System.out.print(summary.toString());
		return null;
	}

	public OCSPRequestor getRequestor() {
		return requestor;
	}

	public void setRequestor(OCSPRequestor requestor) {
		this.requestor = requestor;
	}	
}
