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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.search.controls;


import java.nio.ByteBuffer;

import javax.naming.NamingException;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.Asn1Decoder;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.Asn1Object;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.DecoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.ControlDecoder;


/**
 * A decoder for EntryChangeControls.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EntryChangeControlDecoder extends Asn1Decoder implements ControlDecoder
{
    /** The entry change OID */
    private final static String CONTROL_TYPE_OID = "2.16.840.1.113730.3.4.7";

    /** An instance of this decoder */
    private static final Asn1Decoder decoder = new Asn1Decoder();

    /**
     * @return The Entry Change controm OID
     */
    public String getControlType()
    {
        return CONTROL_TYPE_OID;
    }

    /**
     * Decode the entry change control
     * 
     * @param controlBytes The bytes array which contains the encoded entry change
     * 
     * @return A valid EntryChange object
     * 
     * @throws DecoderException If the decoding found an error
     * @throws NamingException It will never be throw by this method
     */
    
    public Asn1Object decode( byte[] controlBytes ) throws DecoderException, NamingException
    {
        ByteBuffer bb = ByteBuffer.wrap( controlBytes );
        EntryChangeControlContainer container = new EntryChangeControlContainer();
        decoder.decode( bb, container );
        return container.getEntryChangeControl();
    }
}
