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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.message.extended;

import java.nio.ByteBuffer;

import javax.naming.NamingException;
import javax.naming.ldap.ExtendedResponse;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.EncoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.NotImplementedException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.extended.operations.StoredProcedure;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.extended.operations.StoredProcedureContainer;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.extended.operations.StoredProcedureDecoder;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.extended.operations.StoredProcedure.StoredProcedureParameter;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ExtendedRequestImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ResultResponse;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.StringTools;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An extended operation requesting the server to execute a stored procedure.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$
 */
public class StoredProcedureRequest extends ExtendedRequestImpl
{
    private static final Logger log = LoggerFactory.getLogger( StoredProcedureRequest.class );
    private static final long serialVersionUID = -4682291068700593492L;
    public static final String EXTENSION_OID = "1.3.6.1.4.1.18060.0.1.6";

    private StoredProcedure procedure;

    
    public StoredProcedureRequest( int messageId )
    {
        super( messageId );
        this.setOid( EXTENSION_OID );
        this.procedure = new StoredProcedure();
    }


    public StoredProcedureRequest( int messageId, String procedure, String language )
    {
        super( messageId );
        this.setOid( EXTENSION_OID );
        this.procedure = new StoredProcedure();
        this.setLanguage( language );
        this.setProcedure( procedure );
    }


    private void encodePayload() throws EncoderException
    {
        payload = procedure.encode( null ).array();
    }


    public void setPayload( byte[] payload )
    {
        StoredProcedureDecoder decoder = new StoredProcedureDecoder();
        StoredProcedureContainer container = new StoredProcedureContainer();
        
        try
        {
            decoder.decode( ByteBuffer.wrap( payload ), container );
            this.procedure = container.getStoredProcedure();
        }
        catch ( Exception e )
        {
            log.error( "failed to decode payload", e );
            throw new RuntimeException( e );
        }
    }


    public ExtendedResponse createExtendedResponse( String id, byte[] berValue, int offset, int length )
        throws NamingException
    {
    	StoredProcedureResponse resp = ( StoredProcedureResponse ) getResultResponse();
    	resp.setResponse( berValue );
    	resp.setOid( id );
        return ( ExtendedResponse ) resp;
    }


    public byte[] getEncodedValue()
    {
        return getPayload();
    }


    public byte[] getPayload()
    {
        if ( payload == null )
        {
            try
            {
                encodePayload();
            }
            catch ( EncoderException e )
            {
                log.error( "Failed to encode payload StoredProcedureRequest", e );
                throw new RuntimeException( e );
            }
        }

        return payload;
    }


    public ResultResponse getResultResponse()
    {
        if ( response == null )
        {
            StoredProcedureResponse spr = new StoredProcedureResponse( getMessageId() );
            spr.setOid( EXTENSION_OID );
            response = spr;
        }

        return response;
    }


    // -----------------------------------------------------------------------
    // Parameters of the Extended Request Payload
    // -----------------------------------------------------------------------


    public String getLanguage()
    {
        return procedure.getLanguage();
    }
    
    
    public void setLanguage( String language )
    {
        this.procedure.setLanguage( language );
    }

    
    public void setProcedure( String procedure )
    {
        this.procedure.setProcedure( StringTools.getBytesUtf8( procedure ) );
    }

    
    public String getProcedureSpecification()
    {
        return StringTools.utf8ToString( procedure.getProcedure() );
    }
    
    
    public int size()
    {
        return this.procedure.getParameters().size();
    }
    
    
    public Object getParameterType( int index )
    {
        if ( ! this.procedure.getLanguage().equals( "java" ) )
        {
            return ( ( StoredProcedureParameter ) procedure.getParameters().get( index ) ).getType();
        }

        return getJavaParameterType( index );
    }
    
    
    public Class getJavaParameterType( int index )
    {
        throw new NotImplementedException( "class loading of procedure type not implemented" );
    }
    
    
    public Object getParameterValue( int index )
    {
        if ( ! this.procedure.getLanguage().equals( "java" ) )
        {
            return ( ( StoredProcedureParameter ) procedure.getParameters().get( index ) ).getValue();
        }

        return getJavaParameterValue( index );
    }
    
    
    public Object getJavaParameterValue( int index )
    {
        throw new NotImplementedException( "conversion of value to java type not implemented" );
    }
    
    
    public void addParameter( Object type, Object value )
    {
        /**
         *
         * FIXME: Why do we check here whether it's Java or not ?
         * Codec has nothing to do with these details.
         *
         if ( ! this.procedure.getLanguage().equals( "java" ) )
         {
             StoredProcedureParameter parameter = new StoredProcedureParameter();
             parameter.setType( ( byte[] ) type );
             parameter.setValue( ( byte[] ) value );
             this.procedure.addParameter( parameter );
         }
         
         * Replacing this code with the one below without the conditional check.
         
         */
        
        StoredProcedureParameter parameter = new StoredProcedureParameter();
        parameter.setType( ( byte[] ) type );
        parameter.setValue( ( byte[] ) value );
        this.procedure.addParameter( parameter );

        // below here try to convert parameters to their appropriate byte[] representations
        
        /**
         * FIXME: What is this for?
         * 
         * throw new NotImplementedException( "conversion of value to java type not implemented" );
         */
    }
}
