/**
 * Interface representing Keycloak client attributes, including token expiry options.
 */
export interface KeycloakClientAttributes {
  // Token expiry attributes (in seconds)
  accessTokenLifespan?: string; // e.g., "3600"
  refreshTokenLifespan?: string; // e.g., "1800"
  clientSessionIdleTimeout?: string;
  clientSessionMaxLifespan?: string;
  // SAML and custom attributes
  "saml.assertion.signature"?: string;
  "saml.force.post.binding"?: string;
  "saml.multivalued.roles"?: string;
  "saml.encrypt"?: string;
  "saml.server.signature"?: string;
  "saml.server.signature.keyinfo.ext"?: string;
  "saml.artifact.binding.identifier"?: string;
  "saml.artifact.binding"?: string;
  "saml.artifact.binding.mapping"?: string;
  "saml.authnstatement"?: string;
  "saml.onetimeuse.condition"?: string;
  "saml_name_id_format"?: string;
  "saml_signature_algorithm"?: string;
  "saml_signing_certificate"?: string;
  "saml_signing_private_key"?: string;
  [key: string]: any; // For custom attributes
}
