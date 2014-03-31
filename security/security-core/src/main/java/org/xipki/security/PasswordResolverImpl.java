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

package org.xipki.security;

import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SinglePasswordResolver;

public class PasswordResolverImpl implements PasswordResolver {
	private ConcurrentLinkedQueue<SinglePasswordResolver> resolvers = new ConcurrentLinkedQueue<SinglePasswordResolver>();
	
	public PasswordResolverImpl() {
	}
	
	public void setPasswordResolvers(List<SinglePasswordResolver> resolvers)
	{
		this.resolvers = new ConcurrentLinkedQueue<SinglePasswordResolver>(resolvers);
	}
	
	public void removePasswordResolver(SinglePasswordResolver resolver)
	{
		resolvers.remove(resolver);
	}
	
	public char[] resolvePassword(String passwordHint) throws PasswordResolverException
	{
		int index = passwordHint.indexOf(':'); 
		if(index == -1)
		{
			return passwordHint.toCharArray();
		}
		
		String protocol = passwordHint.substring(0, index);
		
		
		for(SinglePasswordResolver resolver : resolvers)
		{
			if(resolver.canResolveProtocol(protocol))
			{
				return resolver.resolvePassword(passwordHint);
			}
		}
		
		return passwordHint.toCharArray();
	}

}
