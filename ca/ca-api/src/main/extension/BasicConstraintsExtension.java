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

package lca.ca.profile.extension;


public class BasicConstraintsExtension extends ExtensionConf {
    private boolean ca;
    private int pathLenConstraint;


    public void setCa(boolean ca) {
        this.ca = ca;
    }

    public void setPathLenConstraint(int pathLenConstraint) {
        this.pathLenConstraint = pathLenConstraint;
    }

    public boolean isCa() {
        return ca;
    }

    public int getPathLenConstraint() {
        return pathLenConstraint;
    }

}
