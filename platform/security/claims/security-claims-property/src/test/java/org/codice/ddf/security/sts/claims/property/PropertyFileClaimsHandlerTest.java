/**
 * Copyright (c) Codice Foundation
 *
 * <p>This is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public
 * License is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package org.codice.ddf.security.sts.claims.property;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ddf.security.claims.ClaimsCollection;
import ddf.security.claims.ClaimsParameters;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class PropertyFileClaimsHandlerTest {

  @Rule public TemporaryFolder temporaryFolder = new TemporaryFolder();

  @Test
  public void testRetrieveClaimValues() throws IOException {
    PropertyFileClaimsHandler propertyFileClaimsHandler = new PropertyFileClaimsHandler();
    propertyFileClaimsHandler.setPropertyFileLocation(
        createFilePathFromResourceFileName("/users.properties"));
    propertyFileClaimsHandler.setRoleClaimType("http://myroletype");
    propertyFileClaimsHandler.setIdClaimType("http://myidtype");

    ClaimsParameters claimsParameters = mock(ClaimsParameters.class);
    Principal principal = mock(Principal.class);
    when(principal.getName()).thenReturn("admin");
    when(claimsParameters.getPrincipal()).thenReturn(principal);
    ClaimsCollection processedClaimCollection =
        propertyFileClaimsHandler.retrieveClaims(claimsParameters);

    assertEquals(2, processedClaimCollection.size());
    assertEquals(4, processedClaimCollection.get(0).getValues().size());
    assertEquals("admin", processedClaimCollection.get(1).getValues().get(0));
  }

  @Test
  public void testGetUser() {
    PropertyFileClaimsHandler propertyFileClaimsHandler = new PropertyFileClaimsHandler();

    Principal principal = mock(Principal.class);
    when(principal.getName()).thenReturn("mydude");
    String user = propertyFileClaimsHandler.getUser(principal);
    assertEquals("mydude", user);

    principal = new X500Principal("cn=myxman,ou=someunit,o=someorg");
    user = propertyFileClaimsHandler.getUser(principal);
    assertEquals("myxman", user);

    principal = new KerberosPrincipal("mykman@SOMEDOMAIN.COM");
    user = propertyFileClaimsHandler.getUser(principal);
    assertEquals("mykman", user);
  }

  @Test
  public void testRetrieveClaimValuesWithGroups() throws IOException {
    PropertyFileClaimsHandler propertyFileClaimsHandler = new PropertyFileClaimsHandler();
    propertyFileClaimsHandler.setPropertyFileLocation(
        createFilePathFromResourceFileName("/usersAndGroups.properties"));
    propertyFileClaimsHandler.setRoleClaimType("http://myroletype");
    propertyFileClaimsHandler.setIdClaimType("http://myidtype");

    ClaimsParameters claimsParametersAdmin = mock(ClaimsParameters.class);
    Principal principalAdmin = mock(Principal.class);
    when(principalAdmin.getName()).thenReturn("admin");
    when(claimsParametersAdmin.getPrincipal()).thenReturn(principalAdmin);
    ClaimsCollection processedClaimCollectionAdmin =
        propertyFileClaimsHandler.retrieveClaims(claimsParametersAdmin);

    assertEquals(2, processedClaimCollectionAdmin.size());

    assertEquals("admin", processedClaimCollectionAdmin.get(1).getValues().get(0));
    assertTrue(processedClaimCollectionAdmin.get(0).getValues().contains("can-read"));
    assertTrue(processedClaimCollectionAdmin.get(0).getValues().contains("can-write"));
    assertTrue(processedClaimCollectionAdmin.get(0).getValues().contains("admin"));
    assertTrue(processedClaimCollectionAdmin.get(0).getValues().contains("manager"));
    assertTrue(processedClaimCollectionAdmin.get(0).getValues().contains("viewer"));

    ClaimsParameters claimsParameterslocalHost = mock(ClaimsParameters.class);
    Principal principalLocalHost = mock(Principal.class);
    when(principalLocalHost.getName()).thenReturn("localhost");
    when(claimsParameterslocalHost.getPrincipal()).thenReturn(principalLocalHost);
    ClaimsCollection processedClaimCollectionLocalhost =
        propertyFileClaimsHandler.retrieveClaims(claimsParameterslocalHost);

    assertEquals("localhost", processedClaimCollectionLocalhost.get(1).getValues().get(0));
    assertTrue(processedClaimCollectionLocalhost.get(0).getValues().contains("can-read"));
    assertTrue(processedClaimCollectionLocalhost.get(0).getValues().contains("admin"));
    assertTrue(processedClaimCollectionLocalhost.get(0).getValues().contains("manager"));
    assertTrue(processedClaimCollectionLocalhost.get(0).getValues().contains("viewer"));
    assertTrue(processedClaimCollectionLocalhost.get(0).getValues().contains("codice-history"));
    assertTrue(
        processedClaimCollectionLocalhost.get(0).getValues().contains("localhost-data-manager"));
  }

  private String createFilePathFromResourceFileName(final String resourceFileName)
      throws IOException {
    final InputStream resourceAsStream =
        PropertyFileClaimsHandlerTest.class.getResourceAsStream(resourceFileName);
    final File userFile = temporaryFolder.newFile(resourceFileName);
    final FileOutputStream userFileOs = new FileOutputStream(userFile);
    IOUtils.copy(resourceAsStream, userFileOs);

    return userFile.getAbsolutePath();
  }
}
