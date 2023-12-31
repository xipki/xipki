// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api;

import org.xipki.datasource.DataSourceWrapper;

/**
 * Interface to get data source by the name.
 *
 * @author Lijun Liao (xipki)
 */
public interface DataSourceMap {

  DataSourceWrapper getDataSource(String name);

}
