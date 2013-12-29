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

package net.sourceforge.myvd.protocol.ldap.mina.asn1.codec;


/**
 * Defines common decoding methods for byte array decoders.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Id: BinaryDecoder.java 437004 2008-08-25 22:53:17 +0000 (Fri, 25 Aug 2008) elecharny $
 */
public interface BinaryDecoder extends Decoder
{

    /**
     * Decodes a byte array and returns the results as a byte array.
     * 
     * @param pArray
     *            A byte array which has been encoded with the appropriate
     *            encoder
     * @return a byte array that contains decoded content
     * @throws net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.DecoderException
     *             A decoder exception is thrown if a Decoder encounters a
     *             failure condition during the decode process.
     */
    byte[] decode( byte[] pArray ) throws DecoderException;
}
