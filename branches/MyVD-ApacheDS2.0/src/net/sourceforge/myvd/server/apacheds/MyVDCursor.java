package net.sourceforge.myvd.server.apacheds;

import net.sourceforge.myvd.types.Results;

import org.apache.directory.api.ldap.model.cursor.AbstractCursor;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;

public class MyVDCursor extends AbstractCursor<Entry> {

	
	
	private Results res;
	LdapException le;
	boolean first;
	
	net.sourceforge.myvd.types.Entry buffer;

	public MyVDCursor(Results res) {
		this.res = res;
		le = null;
		first = true;
		buffer = null;
	}
	
	@Override
	public void after(Entry arg0) throws LdapException, CursorException {
		//Do nothing
		
	}

	@Override
	public void afterLast() throws LdapException, CursorException {
		
		if (le != null) {
			throw le;
		}
		
		try {
			while (res.hasMore()) res.next();
			le = null;
		} catch (LDAPException e) {
			throw MyVDPartition.generateException(e);
		}
		
	}

	@Override
	public boolean available() {
		try {
			return res.hasMore();
		} catch (LDAPException e) {
			this.le =  MyVDPartition.generateException(e);
			return true;
		}
	}

	@Override
	public void before(Entry arg0) throws LdapException, CursorException {
		//do nothing
		
	}

	@Override
	public void beforeFirst() throws LdapException, CursorException {
		//do nothing
		
	}

	@Override
	public boolean first() throws LdapException, CursorException {
		return this.first;
	}

	@Override
	public Entry get() throws CursorException {
		
		try {
			LDAPEntry nentry = null;
			
			if (buffer != null) {
				nentry = buffer.getEntry();
				buffer = null;
			} else {
				nentry = res.next().getEntry();
			}
			
			Entry entry = new DefaultEntry();
			
			entry.setDn(nentry.getDN());
			LDAPAttributeSet attrs = nentry.getAttributeSet();
			for (Object o : attrs) {
				LDAPAttribute a = (LDAPAttribute) o;
				byte[][] vals = a.getByteValueArray();
				for (int i=0;i<vals.length;i++) {
					entry.add(a.getName(),vals[i]);
				}
			}
			
			return entry;
		} catch (Exception e) {
			throw new CursorException(e);
		} 
		
	}

	@Override
	public boolean last() throws LdapException, CursorException {
		
		try {
			while (res.hasMore()) {
				buffer = res.next();
			}
			return true;
		} catch (LDAPException e) {
			throw MyVDPartition.generateException(e);
		}
	}

	@Override
	public boolean next() throws LdapException, CursorException {
		try {
			return res.hasMore();
		} catch (LDAPException e) {
			throw MyVDPartition.generateException(e);
		}
	}

	@Override
	public boolean previous() throws LdapException, CursorException {
		
		return false;
	}

}
