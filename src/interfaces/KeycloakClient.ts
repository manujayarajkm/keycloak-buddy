/**
 * Interface representing a Keycloak client object, including token expiry options.
 */
import { KeycloakClientAttributes } from "./KeycloakClientAttributes";

export interface KeycloakClient {
  clientId: string;
  enabled?: boolean;
  protocol?: string;
  redirectUris?: string[];
  baseUrl?: string;
  publicClient?: boolean;
  secret?: string;
  directAccessGrantsEnabled?: boolean;
  standardFlowEnabled?: boolean;
  implicitFlowEnabled?: boolean;
  serviceAccountsEnabled?: boolean;
  rootUrl?: string;
  description?: string;
  attributes?: KeycloakClientAttributes;
  accessTokenLifespan?: number; // in seconds
  refreshTokenLifespan?: number; // in seconds
  clientSessionIdleTimeout?: number;
  clientSessionMaxLifespan?: number;
}
