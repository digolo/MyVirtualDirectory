/**
 * Copyright (c) 2006 Novell, Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; version 2.1 of the license.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, contact Novell, Inc.
 *
 * To contact Novell about this file by physical or electronic mail,
 * you may find current contact information at www.novell.com
 * 
 * Changes Copyright (c) 2007 Marc Boorshtein
 */

package net.sourceforge.myvd.higgins.idas.contextProvider;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.util.HashSet;
import java.util.Properties;

import net.sourceforge.myvd.higgins.idas.contextProvider.config.MyVDHigginsConfig;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.exception.LdapNamingException;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.server.Server;

import org.apache.log4j.PropertyConfigurator;
import org.eclipse.higgins.idas.IContext;
import org.eclipse.higgins.idas.IContextFactory;
import org.eclipse.higgins.idas.IMetadata;
import org.eclipse.higgins.idas.IPropertyValue;
import org.eclipse.higgins.idas.IdASException;
import org.eclipse.higgins.idas.NotImplementedException;
import org.eclipse.higgins.idas.impl.BasicMetadata;
import org.exolab.castor.xml.MarshalException;
import org.exolab.castor.xml.ValidationException;

import com.novell.ldap.LDAPException;

/**
*
* @author jimse@novell.com
* @author tdoman@novell.com
*
*/

public class MyVDContextFactory implements IContextFactory
{
	private HashSet<IMetadata> _metaData;
	private MyVDHigginsConfig cfg;
	private String propsConfig;
	private String searchBase;
	private String uidAttrib;
	private Server server;
	private Insert[] globalChain;
	private Router router;

	/**
	 */
	public String getName() throws IdASException
	{
		return "MyVirtualDirectory Context Provider";
	}

	/**
	 */
	public Iterable<URI> getContexts(
	    String arg0) throws IdASException
	{
		throw new NotImplementedException();
	}

	/**
	 */
	public boolean canCreate(
		URI contextRef) throws IdASException
	{
		boolean bRet = false;
		try
		{
			this.createContext(contextRef);
			bRet = true;
		}
		catch (IdASException e)
		{
			bRet = false;
		}
		return bRet;
	}

	/**
	 */
	public IContext createContext(
		URI contextRef) throws IdASException
	{
		Properties props = new Properties();
		props.put("log4j.rootLogger", "DEBUG,console");
		props.put("log4j.appender.console","org.apache.log4j.ConsoleAppender");
		props.put("log4j.appender.console.layout","org.apache.log4j.PatternLayout");
		props.put("log4j.appender.console.layout.ConversionPattern","[%d][%t] %-5p %c{1} - %m%n");
		PropertyConfigurator.configure(props);
		
		try {
		
		if (contextRef.getScheme().compareTo("file") == 0)
		{
			try
			{
				FileReader fileReader = new FileReader(contextRef.getPath());
				cfg = MyVDHigginsConfig.unmarshal(fileReader);
				
				this.propsConfig = cfg.getConfigFile();
				this.searchBase = cfg.getUserSearchBase();
				this.uidAttrib = cfg.getUserIdAttribute();
				
				/*
				
				
				
				RealmsType realmsType = Realms.unmarshal(fileReader);

				for (int iLoop = 0; iLoop < realmsType.getRealmsTypeItemCount(); ++iLoop)
				{
					RealmsTypeItem realmsTypeItem = realmsType.getRealmsTypeItem(iLoop);
					Realm realm = realmsTypeItem.getRealm();
					String query = _contextRef.getQuery();
					//TODO: Hack out just the "id" piece from any other query items
					if (realm.getId().compareToIgnoreCase(query.substring(query.indexOf("id=") + 3)) == 0)
					{
						_targetRealm = realm;
						break out;
					}
				} */
			}
			catch (FileNotFoundException e)
			{
				throw new IdASException(e);
			}
			catch (MarshalException e)
			{
				throw new IdASException(e);
			}
			catch (ValidationException e)
			{
				throw new IdASException(e);
			}
		}
		else
		{
			throw new NotImplementedException("Specified scheme not supported: " + contextRef.getScheme());
		}
		
//		TODO add initialization code here...init the 
		try {
			if (server == null) {
				System.out.println("props file : " + this.propsConfig);
				server = new Server(this.propsConfig);
				
				server.startServer();
				
				globalChain = server.getGlobalChain();
				router = server.getRouter();
			}
			return new MyVDContext(globalChain,router,contextRef,cfg);
		} catch (FileNotFoundException e) {
			throw new IdASException(e);
		} catch (IOException e) {
			throw new IdASException(e);
		} catch (LdapNamingException e) {
			throw new IdASException(e);
		} catch (InstantiationException e) {
			throw new IdASException(e);
		} catch (IllegalAccessException e) {
			throw new IdASException(e);
		} catch (ClassNotFoundException e) {
			throw new IdASException(e);
		} catch (LDAPException e) {
			throw new IdASException(e);
		} catch (Throwable t) {
			throw new IdASException(t);
		}
		} catch (IdASException e) {
			e.printStackTrace();
			throw e;
		}
				
	}

	/**
	 */
	public String getPolicy() throws IdASException
	{
		throw new NotImplementedException();
	}

	/**
	 */
	public void setPolicy(
		String arg0) throws IdASException
	{
		throw new NotImplementedException();
	}

	/**
	 */
	public IMetadata createMetadata(
		URI type,
		IPropertyValue value) throws IdASException
	{
		return new BasicMetadata(type, value);
	}

	/**
	 */
	public void addMetadata(
		IMetadata metadata) throws IdASException
	{
		_getMetadataSet().add(metadata);
	}

	/**
	 */
	public void	removeMetadata(
		IMetadata metadata) throws IdASException
	{
		_getMetadataSet().remove(metadata);
	}

	/**
	 */
	public Iterable<IMetadata> getMetadataSet() throws IdASException
	{
		return _getMetadataSet();
	}

	/**
	 */
	private HashSet<IMetadata> _getMetadataSet() throws IdASException
	{
		if (_metaData == null)
			_metaData = new HashSet<IMetadata>();
		return _metaData;
	}
}
