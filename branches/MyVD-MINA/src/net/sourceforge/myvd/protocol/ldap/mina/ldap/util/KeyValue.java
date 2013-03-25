/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package net.sourceforge.myvd.protocol.ldap.mina.ldap.util;


/**
 * Defines a simple key value pair.
 * <p>
 * A Map Entry has considerable additional semantics over and above a simple
 * key-value pair. This interface defines the minimum key value, with just the
 * two get methods.
 * 
 * @since Commons Collections 3.0
 * @version $Revision: 437007 $ $Date: 2006-08-25 23:06:17 +0000 (Fri, 25 Aug 2006) $
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface KeyValue
{

    /**
     * Gets the key from the pair.
     * 
     * @return the key
     */
    Object getKey();


    /**
     * Gets the value from the pair.
     * 
     * @return the value
     */
    Object getValue();

}