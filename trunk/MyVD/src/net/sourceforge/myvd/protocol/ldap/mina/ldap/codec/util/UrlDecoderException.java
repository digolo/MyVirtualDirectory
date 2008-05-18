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

package net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.util;


/**
 * Thrown when a Decoder has encountered a failure condition during a decode.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Id: UrlDecoderException.java 437007 2008-08-25 23:06:17 +0000 (Fri, 25 Aug 2008) elecharny $
 */
public class UrlDecoderException extends Exception
{
    final static long serialVersionUID = 1L;


    /**
     * Creates a DecoderException
     * 
     * @param pMessage
     *            A message with meaning to a human
     */
    public UrlDecoderException(String pMessage)
    {
        super( pMessage );
    }

}
