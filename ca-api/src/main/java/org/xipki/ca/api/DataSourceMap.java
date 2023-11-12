package org.xipki.ca.api;

import org.xipki.datasource.DataSourceWrapper;

public interface DataSourceMap {

  DataSourceWrapper getDataSource(String name);

}
