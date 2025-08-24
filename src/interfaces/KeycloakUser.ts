/**
 * Interface representing a Keycloak user object.
 */
export interface KeycloakUser {
  username: string;
  enabled?: boolean;
  email?: string;
  firstName?: string;
  lastName?: string;
  attributes?: Record<string, any>;
  credentials?: Array<{
    type: string;
    value: string;
    temporary?: boolean;
  }>;
  requiredActions?: string[];
  groups?: string[];
  realmRoles?: string[];
  clientRoles?: Record<string, string[]>;
}
