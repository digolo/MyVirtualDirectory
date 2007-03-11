package net.sourceforge.myvd.higgins.idas.contextProvider.test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Vector;


import org.bandit.util.config.gen.Env;
import org.bandit.util.config.gen.LDAPConnector;
import org.bandit.util.config.gen.Realm;
import org.bandit.util.config.gen.RealmTypeItem;
import org.bandit.util.config.gen.Realms;
import org.bandit.util.config.gen.RealmsTypeItem;
import org.bandit.util.config.gen.types.ConnectorTypeType;
import org.eclipse.higgins.idas.IAttribute;
import org.eclipse.higgins.idas.IContext;
import org.eclipse.higgins.idas.IContextFactory;
import org.eclipse.higgins.idas.IDigitalSubject;
import org.eclipse.higgins.idas.IFilter;
import org.eclipse.higgins.idas.IFilterAttributeAssertion;
import org.eclipse.higgins.idas.IFilterPropertyAssertion;
import org.eclipse.higgins.idas.IPropertyValue;
import org.eclipse.higgins.idas.IdASException;
import org.eclipse.higgins.idas.IdASRegistry;
import org.eclipse.higgins.idas.impl.BasicValueString;
import org.exolab.castor.xml.MarshalException;
import org.exolab.castor.xml.ValidationException;

import net.sourceforge.myvd.higgins.idas.contextProvider.MyVDContextFactory;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import junit.framework.TestCase;

public class TestMyVDCP extends TestCase {

	private StartOpenLDAP testServer;

	protected void setUp() throws Exception {
		this.testServer = new StartOpenLDAP();
		System.setProperty("nolog","1");
		this.testServer.startServer(System.getenv("PROJ_DIR") + "/myvd-test/novel-openldap",50389,"cn=admin,o=bandit","manager");
	}


	
	public void testContextProvider()
	{
		_createRealmsFile();
		_runContextTest();
		_runRegistryTest();
	}

	private void _runRegistryTest()
	{
		IdASRegistry reg = new IdASRegistry();
		Iterable<IContextFactory> factories = reg.getContextFactories("");

		for (IContextFactory factory : factories)
		{
			try
			{
				System.out.println(factory.getName());
				File configFile = new File("conf/context.config.xml");
				URI configURI = new URI(configFile.toURI().toString() + "?id=Corporate-LDAP-Server");
				boolean bCanCreate = factory.canCreate(configURI);
				System.out.println((bCanCreate ? "" : "NOT ") + "CREATABLE: " + configURI.toString());
			}
			catch (IdASException e)
			{
				e.printStackTrace();
			}
			catch (URISyntaxException e)
			{
				e.printStackTrace();
			}
		}
	}

	private void _createRealmsFile()
	{
		Realms testRealm = new Realms();
		RealmsTypeItem realmsItem = new RealmsTypeItem();
		Realm realm = new Realm();
		RealmTypeItem connRealmItem = new RealmTypeItem(), envRealmItem = new RealmTypeItem();

		realm.setDesc("LDAP Directory: Bandit");
		realm.setId("6289E76C-0883-49f1-9DCE-85293A83ED3E");
		realm.setConnectorType(ConnectorTypeType.ORG_BANDIT_IA_CONNECTORS_LDAPCONNECTORINITIALCTXFACTORY);
		LDAPConnector ldapConn = new LDAPConnector();
		ldapConn.addAddress("ldap://localhost:50389");
		connRealmItem.setConnection(ldapConn);
		realm.addRealmTypeItem(connRealmItem);
		Env env = new Env();
		env.setProp("java.naming.ldap.attributes.binary");
		env.setValue("guid");
		envRealmItem.addEnv(env);
		realm.addRealmTypeItem(envRealmItem);
		realmsItem.setRealm(realm);
		testRealm.addRealmsTypeItem(realmsItem);

		try
		{
			FileWriter realmFile = new FileWriter("testRealm.xml");
			testRealm.marshal(realmFile);
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
		catch (MarshalException e)
		{
			e.printStackTrace();
		}
		catch (ValidationException e)
		{
			e.printStackTrace();
		}
	}

	private void _runContextTest()
	{
		IContext context = null;
		try
		{
			IContextFactory factory = new MyVDContextFactory();
			File configFile = new File("testRealm.xml");
			URI configURI = new URI(configFile.toURI().toString() + "?id=6289E76C-0883-49f1-9DCE-85293A83ED3E");
			context = factory.createContext(configURI);

			if (context != null)
			{
				Iterable<IDigitalSubject> subjects;

				context.open("Fix this!");

				IFilter ocFilter = context.createFilter();
				IFilterAttributeAssertion attrAssertion = ocFilter.createAttributeAssertion();
				attrAssertion.setType(new URI("http://www.eclipse.org/higgins/ontologies/2006/higgins/ldap#attr_objectclass"));
				attrAssertion.setComparator(IFilterPropertyAssertion.COMP_PROP_PRESENT);
				ocFilter.setAssertion(attrAssertion);

				IFilter cnFilter = context.createFilter();
				attrAssertion = cnFilter.createAttributeAssertion();
				attrAssertion.setType(new URI("http://www.eclipse.org/higgins/ontologies/2006/higgins/ldap#attr_cn"));
				attrAssertion.setComparator(IFilterPropertyAssertion.COMP_PROP_EQ);
				BasicValueString assertionValue = new BasicValueString("tdoman");
				attrAssertion.setAssertionValue(assertionValue);
				cnFilter.setAssertion(attrAssertion);

				IFilter filter = context.createFilter();
				filter.setOperator(IFilter.OP_AND);
				filter.addFilter(ocFilter);
				filter.addFilter(cnFilter);

				subjects = context.getSubjects(filter);
				for (IDigitalSubject subject : subjects)
				{
					Iterable<IAttribute> attrs = subject.getAttributes();
					System.out.println(subject.getUniqueID());
					System.out.println(subject.getType());

					for (IAttribute attr : attrs)
					{
						Iterable<IPropertyValue> propValues = attr.getValues();
						System.out.println(attr.getType());

						for (IPropertyValue propVal : propValues)
						{
							Object val = propVal.getData();
							if (val instanceof String)
								System.out.println(val);
							else
								System.out.println("Unknown: " + val.toString());
						}
					}
				}

				Vector<URI> attrs = new Vector<URI>();
				attrs.add(new URI("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"));
				attrs.add(new URI("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier"));
				IDigitalSubject subject = context.getSubject("cn=tdoman,ou=people,o=bandit", attrs);
				System.out.println("subject : " + subject);
				System.out.println(subject.getUniqueID());

				FileWriter owlFile = new FileWriter("test.owl");
				owlFile.write(context.getSchema());
				owlFile.flush();

				context.close();
			}
		}
		catch (IdASException e)
		{
			e.printStackTrace();
		}
		catch (URISyntaxException e)
		{
			e.printStackTrace();
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}
	
	protected void tearDown() throws Exception {
		this.testServer.stopServer();
	}

}
