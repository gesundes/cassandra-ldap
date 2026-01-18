/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.instaclustr.cassandra.ldap.auth;

import static java.lang.String.format;

import javax.naming.Context;
import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

import com.instaclustr.cassandra.ldap.User;
import com.instaclustr.cassandra.ldap.auth.DefaultLDAPServer.LDAPInitialContext.CloseableLdapContext;
import com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration;
import com.instaclustr.cassandra.ldap.exception.LDAPAuthFailedException;
import com.instaclustr.cassandra.ldap.hash.Hasher;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.exceptions.ExceptionCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DefaultLDAPServer extends LDAPUserRetriever
{
    private static final Logger logger = LoggerFactory.getLogger(DefaultLDAPServer.class);

    static class LDAPInitialContext implements AutoCloseable
    {
        private static final Logger logger = LoggerFactory.getLogger(LDAPInitialContext.class);

        private CloseableLdapContext ldapContext;
        private Properties properties;

        private static final String MEMBER_OF_ATTRIBUTE = "memberOf";
        private static final String GROUP_MEMBER_ATTRIBUTE = "member";
        private static final String GROUP_UNIQUE_MEMBER_ATTRIBUTE = "uniqueMember";

        private final LdapName baseDn;
        private final String rootLdapUri;

        public LDAPInitialContext(final Properties properties)
        {
            this.properties = properties;
            this.baseDn = parseBaseDn(properties.getProperty(LdapAuthenticatorConfiguration.LDAP_URI_PROP));

            final Properties ldapProperties = new Properties();

            final String serviceDN = properties.getProperty(LdapAuthenticatorConfiguration.LDAP_DN);
            final String servicePass = properties.getProperty(LdapAuthenticatorConfiguration.PASSWORD_KEY);
            final String ldapUri = properties.getProperty(LdapAuthenticatorConfiguration.LDAP_URI_PROP);

            ldapProperties.put(Context.INITIAL_CONTEXT_FACTORY, properties.getProperty(LdapAuthenticatorConfiguration.CONTEXT_FACTORY_PROP));
            ldapProperties.put(Context.PROVIDER_URL, ldapUri);
            ldapProperties.put(Context.SECURITY_PRINCIPAL, serviceDN);
            ldapProperties.put(Context.SECURITY_CREDENTIALS, servicePass);

            this.rootLdapUri = parseRootLdapUri(ldapUri);

            try
            {
                ldapContext = new CloseableLdapContext(new InitialDirContext(ldapProperties));
            }
            catch (final NamingException ex)
            {
                throw new ConfigurationException(format("Failed to connect to LDAP server: %s, explanation: %s",
                                                        ex.getMessage(),
                                                        ex.getExplanation() == null ? "uknown" : ex.getExplanation()),
                                                 ex);
            }
        }

        public static final class CloseableLdapContext implements AutoCloseable
        {

            private final InitialDirContext context;

            CloseableLdapContext(final InitialDirContext context)
            {
                this.context = context;
            }

            @Override
            public void close() throws Exception
            {
                if (context != null)
                {
                    context.close();
                }
            }
        }

        public String searchLdapDN(final String username) throws NamingException
        {
            final String filterTemplate = properties.getProperty(LdapAuthenticatorConfiguration.FILTER_TEMPLATE);
            final String filter = format(filterTemplate, username);

            logger.debug("User name is {}, going to use filter: {}", username, filter);

            String dn = null;

            final SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            NamingEnumeration<SearchResult> answer = null;

            try
            {

                answer = ldapContext.context.search("", filter, searchControls);

                final List<String> resolvedDns = new ArrayList<>();

                if (answer.hasMore())
                {
                    SearchResult result = answer.next();
                    dn = result.getNameInNamespace();
                    resolvedDns.add(dn);
                }

                if (resolvedDns.size() != 1 || resolvedDns.get(0) == null)
                {
                    throw new NamingException(String.format("There is not one DN resolved after search on filter %s: %s. "
                                                                + "User likely does not exist or connection to LDAP server is invalid.", filter, resolvedDns));
                }

                logger.debug("Returning DN: {}", resolvedDns.get(0));

                return dn;
            } catch (final NamingException ex)
            {
                if (answer != null)
                {
                    try
                    {
                        answer.close();
                    } catch (NamingException closingException)
                    {
                        logger.warn("Failing to close connection to LDAP server.");
                    }
                }

                logger.error("Error while searching! " + ex.toString(true) + " explanation: " + ex.getExplanation(), ex);

                throw ex;
            }
        }

        public boolean isUserInGroup(final String userDn, final String groupDn) throws NamingException
        {
            final String normalizedGroupDn = normalizeDn(groupDn);

            if (isMemberOfGroup(userDn, normalizedGroupDn))
            {
                return true;
            }

            return isUserListedInGroup(groupDn, normalizeDn(userDn));
        }

        private boolean isMemberOfGroup(final String userDn, final String normalizedGroupDn) throws NamingException
        {
            try
            {
                final Attributes attributes = getAttributesWithFallback(userDn, new String[] { MEMBER_OF_ATTRIBUTE });
                return attributeContainsDn(attributes.get(MEMBER_OF_ATTRIBUTE), normalizedGroupDn);
            } catch (final NamingException ex)
            {
                logger.debug("Unable to read memberOf for {}", userDn, ex);
                return false;
            }
        }

        private boolean isUserListedInGroup(final String groupDn, final String normalizedUserDn) throws NamingException
        {
            final Attributes attributes = getAttributesWithFallback(groupDn,
                                                                    new String[] { GROUP_MEMBER_ATTRIBUTE, GROUP_UNIQUE_MEMBER_ATTRIBUTE });
            if (attributeContainsDn(attributes.get(GROUP_MEMBER_ATTRIBUTE), normalizedUserDn))
            {
                return true;
            }
            return attributeContainsDn(attributes.get(GROUP_UNIQUE_MEMBER_ATTRIBUTE), normalizedUserDn);
        }

        private boolean attributeContainsDn(final Attribute attribute, final String normalizedDn) throws NamingException
        {
            if (attribute == null)
            {
                return false;
            }

            NamingEnumeration<?> values = null;
            try
            {
                values = attribute.getAll();
                while (values.hasMore())
                {
                    final Object value = values.next();
                    if (value != null && normalizeDn(value.toString()).equals(normalizedDn))
                    {
                        return true;
                    }
                }
            } finally
            {
                if (values != null)
                {
                    values.close();
                }
            }

            return false;
        }

        private Attributes getAttributesWithFallback(final String dn, final String[] attributes) throws NamingException
        {
            NamingException originalException = null;
            try
            {
                return ldapContext.context.getAttributes(toRelativeDn(dn), attributes);
            } catch (final NamingException ex)
            {
                originalException = ex;
            }

            if (rootLdapUri == null || rootLdapUri.equals(properties.getProperty(LdapAuthenticatorConfiguration.LDAP_URI_PROP)))
            {
                throw originalException;
            }

            CloseableLdapContext rootContext = null;
            try
            {
                rootContext = openRootContext();
                return rootContext.context.getAttributes(dn, attributes);
            } catch (final NamingException ex)
            {
                throw originalException;
            } finally
            {
                if (rootContext != null)
                {
                    try
                    {
                        rootContext.close();
                    } catch (final Exception ex)
                    {
                        logger.debug("Unable to close root LDAP context", ex);
                    }
                }
            }
        }

        private CloseableLdapContext openRootContext() throws NamingException
        {
            final Properties ldapProperties = new Properties();

            final String serviceDN = properties.getProperty(LdapAuthenticatorConfiguration.LDAP_DN);
            final String servicePass = properties.getProperty(LdapAuthenticatorConfiguration.PASSWORD_KEY);

            ldapProperties.put(Context.INITIAL_CONTEXT_FACTORY, properties.getProperty(LdapAuthenticatorConfiguration.CONTEXT_FACTORY_PROP));
            ldapProperties.put(Context.PROVIDER_URL, rootLdapUri);
            ldapProperties.put(Context.SECURITY_PRINCIPAL, serviceDN);
            ldapProperties.put(Context.SECURITY_CREDENTIALS, servicePass);

            return new CloseableLdapContext(new InitialDirContext(ldapProperties));
        }

        private String toRelativeDn(final String dn)
        {
            if (dn == null || baseDn == null)
            {
                return dn;
            }

            try
            {
                final LdapName name = new LdapName(dn);
                if (endsWithIgnoreCase(name, baseDn))
                {
                    int prefixSize = name.size() - baseDn.size();
                    if (prefixSize <= 0)
                    {
                        return "";
                    }
                    return name.getPrefix(prefixSize).toString();
                }
            } catch (final InvalidNameException ex)
            {
                logger.debug("Unable to parse DN {}", dn, ex);
            }

            return dn;
        }

        private boolean endsWithIgnoreCase(final LdapName name, final LdapName base)
        {
            if (name == null || base == null)
            {
                return false;
            }

            if (base.size() > name.size())
            {
                return false;
            }

            for (int i = 1; i <= base.size(); i++)
            {
                final String nameRdn = name.get(name.size() - i).toLowerCase(Locale.ROOT);
                final String baseRdn = base.get(base.size() - i).toLowerCase(Locale.ROOT);
                if (!nameRdn.equals(baseRdn))
                {
                    return false;
                }
            }

            return true;
        }

        private LdapName parseBaseDn(final String ldapUri)
        {
            if (ldapUri == null)
            {
                return null;
            }

            try
            {
                final URI uri = new URI(ldapUri);
                final String path = uri.getPath();
                if (path == null || path.isEmpty() || "/".equals(path))
                {
                    return null;
                }

                final String baseDn = path.startsWith("/") ? path.substring(1) : path;
                if (baseDn.isEmpty())
                {
                    return null;
                }

                return new LdapName(baseDn);
            } catch (final Exception ex)
            {
                logger.debug("Unable to parse base DN from ldap_uri {}", ldapUri, ex);
                return null;
            }
        }

        private String parseRootLdapUri(final String ldapUri)
        {
            if (ldapUri == null)
            {
                return null;
            }

            try
            {
                final URI uri = new URI(ldapUri);
                if (uri.getScheme() == null || uri.getHost() == null)
                {
                    return null;
                }

                final URI root = new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), null, null, null);
                return root.toString();
            } catch (final Exception ex)
            {
                logger.debug("Unable to parse root LDAP uri from {}", ldapUri, ex);
                return null;
            }
        }

        private String normalizeDn(final String dn)
        {
            if (dn == null)
            {
                return null;
            }
            return dn.trim().toLowerCase(Locale.ROOT);
        }

        @Override
        public void close() throws IOException {
            if (ldapContext != null)
            {
                try
                {
                    ldapContext.close();
                }
                catch (final Exception ex)
                {
                    throw new IOException(ex);
                }
            }
        }
    }

    @Override
    public UserRetriever setup(final Hasher hasher, final Properties properties) throws ConfigurationException
    {
        this.properties = properties;
        this.hasher = hasher;
        return this;
    }

    @Override
    public User retrieve(User user) throws LDAPAuthFailedException
    {
        try (final LDAPInitialContext context = new LDAPInitialContext(properties))
        {
            final String ldapDn = context.searchLdapDN(user.getUsername());

            logger.debug("Resolved LDAP DN: {}", ldapDn);

            final Hashtable<String, String> env = getUserEnv(ldapDn,
                                                             user.getPassword(),
                                                             properties.getProperty(LdapAuthenticatorConfiguration.CONTEXT_FACTORY_PROP),
                                                             properties.getProperty(LdapAuthenticatorConfiguration.LDAP_URI_PROP));

            try (final CloseableLdapContext ldapContext = new CloseableLdapContext(new InitialDirContext(env)))
            {
                logger.debug("Logging to LDAP with {} was ok!", user);

                final String requiredGroupDn = properties.getProperty(LdapAuthenticatorConfiguration.REQUIRED_GROUP_DN);
                if (requiredGroupDn != null && !context.isUserInGroup(ldapDn, requiredGroupDn))
                {
                    throw new LDAPAuthFailedException(ExceptionCode.UNAUTHORIZED,
                                                      "User " + user.getUsername() + " is not a member of required LDAP group.",
                                                      null);
                }

                final User foundUser = new User(user.getUsername(),
                                          hasher.hashPassword(user.getPassword(),
                                                              LdapAuthenticatorConfiguration.getGensaltLog2Rounds(this.properties)));
                foundUser.setLdapDN(ldapDn);

                return foundUser;
            }
            catch (final NamingException ex)
            {
                throw new LDAPAuthFailedException(ExceptionCode.BAD_CREDENTIALS, ex.getMessage(), ex);
            }
        }
        catch (final Exception ex)
        {
            if (ex instanceof LDAPAuthFailedException)
            {
                throw (LDAPAuthFailedException) ex;
            }
            logger.debug("Error encountered when authenticating via LDAP {}", ex.getMessage());
            throw new LDAPAuthFailedException(ExceptionCode.UNAUTHORIZED, "Not possible to login " + user.getUsername(), ex);
        }
    }

    private Hashtable<String, String> getUserEnv(final String username,
                                                 final String password,
                                                 final String initialContextFactory,
                                                 final String ldapUri)
    {
        final Hashtable<String, String> env = new Hashtable<>(11);

        env.put(Context.INITIAL_CONTEXT_FACTORY, initialContextFactory);
        env.put(Context.PROVIDER_URL, ldapUri);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");

        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);

        return env;
    }
}
