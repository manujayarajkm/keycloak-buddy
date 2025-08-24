/**
 * Interface representing configuration options for Keycloak admin client.
 */
export interface KeycloakAdminOptions {
  baseUrl: string;
  realm: string;
  clientId: string;
  clientSecret?: string;
  username?: string;
  password?: string;
}
