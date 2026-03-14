// #THIRDPARTY
// Copyright (c) Contributors to the Eclipse Foundation
// License: Apache-2.0
package org.osgi.service.component;

import org.osgi.annotation.versioning.ProviderType;

import java.util.Dictionary;

/**
 * Minimal placeholder for OSGi {@code ComponentContext}.
 */
@ProviderType
public interface ComponentContext {

  Dictionary<String, Object> getProperties();

}
