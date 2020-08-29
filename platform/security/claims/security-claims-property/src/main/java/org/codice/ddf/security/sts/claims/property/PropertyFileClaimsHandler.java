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

import ddf.security.claims.Claim;
import ddf.security.claims.ClaimsCollection;
import ddf.security.claims.ClaimsHandler;
import ddf.security.claims.ClaimsParameters;
import ddf.security.claims.impl.ClaimImpl;
import ddf.security.claims.impl.ClaimsCollectionImpl;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.lang.StringUtils;
import org.apache.felix.utils.properties.Properties;
import org.apache.karaf.jaas.boot.principal.RolePrincipal;
import org.apache.karaf.jaas.boot.principal.UserPrincipal;
import org.apache.karaf.jaas.modules.properties.PropertiesBackingEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PropertyFileClaimsHandler implements ClaimsHandler {

  private static final Logger LOGGER = LoggerFactory.getLogger(PropertyFileClaimsHandler.class);

  private String propertyFileLocation;

  private Map<String, String> userMapping;

  private String roleClaimType;

  private String idClaimType;

  @Override
  public ClaimsCollection retrieveClaims(ClaimsParameters parameters) {
    ClaimsCollection claimsColl = new ClaimsCollectionImpl();
    Principal principal = parameters.getPrincipal();
    String user = getUser(principal);
    if (user == null) {
      LOGGER.info(
          "Could not determine user name, possible authentication error. Returning no claims.");
      return claimsColl;
    }

    String userAttributes = userMapping.get(user);
    if (userAttributes != null) {
      String[] attributes = userAttributes.split(",");
      Claim c = new ClaimImpl(roleClaimType);
      for (String attr : attributes) {
        c.addValue(attr);
      }
      claimsColl.add(c);
    }

    Claim idClaim = new ClaimImpl(idClaimType);
    idClaim.addValue(user);
    claimsColl.add(idClaim);

    return claimsColl;
  }

  /**
   * Obtains the user name from the principal.
   *
   * @param principal Describing the current user that should be used for retrieving claims.
   * @return the user name if the principal has one, null if no name is specified or if principal is
   *     null.
   */
  public String getUser(Principal principal) {
    String user = null;
    if (principal instanceof KerberosPrincipal) {
      KerberosPrincipal kp = (KerberosPrincipal) principal;
      StringTokenizer st = new StringTokenizer(kp.getName(), "@");
      user = st.nextToken();
    } else if (principal instanceof X500Principal) {
      X500Principal x500p = (X500Principal) principal;
      StringTokenizer st = new StringTokenizer(x500p.getName(), ",");
      while (st.hasMoreElements()) {
        // token is in the format:
        // syntaxAndUniqueId
        // cn
        // ou
        // o
        // loc
        // state
        // country
        String[] strArr = st.nextToken().split("=");
        if (strArr.length > 1 && strArr[0].equalsIgnoreCase("cn")) {
          user = strArr[1];
          break;
        }
      }
    } else if (principal != null) {
      user = principal.getName();
    }

    return user;
  }

  public void setPropertyFileLocation(String propertyFilePath) {
    if (propertyFilePath != null
        && !propertyFilePath.isEmpty()
        && !propertyFilePath.equals(this.propertyFileLocation)) {

      loadClaimsFromPropertiesFile(new File(propertyFilePath));
    }
    this.propertyFileLocation = propertyFilePath;
  }

  private void loadClaimsFromPropertiesFile(File propertyFile) {

    Properties props = new Properties();

    try {
      props.load(propertyFile);
    } catch (FileNotFoundException e) {
      LOGGER.debug("File not found when attempting to load user properties file.", e);
    } catch (IOException e) {
      LOGGER.debug("Exception when trying to load the user properties file.", e);
    }

    PropertiesBackingEngine propBackingEngine = new PropertiesBackingEngine(props);

    List<UserPrincipal> userList = propBackingEngine.listUsers();
    userMapping = new HashMap();
    for (UserPrincipal eachUser : userList) {

      List<RolePrincipal> userRoles = propBackingEngine.listRoles(eachUser);
      List<String> roleList = new ArrayList<>();
      for (RolePrincipal userRole : userRoles) {
        roleList.add(userRole.getName());
      }

      userMapping.put(eachUser.getName(), StringUtils.join(roleList, ","));
    }
  }

  public void setRoleClaimType(String roleClaimType) {
    this.roleClaimType = roleClaimType;
  }

  public void setIdClaimType(String idClaimType) {
    this.idClaimType = idClaimType;
  }
}
