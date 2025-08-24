// KeycloakAdmin.ts

import axios, { AxiosInstance } from "axios";
import {
  KeycloakUser,
  KeycloakClient,
  KeycloakClientAttributes,
  KeycloakAdminOptions,
} from "../interfaces/index";

export class KeycloakAdmin {
  private readonly axios: AxiosInstance;
  private readonly options: KeycloakAdminOptions;
  private accessToken: string | null = null;

  /**
   * Creates a new KeycloakAdmin client instance.
   * @param options Configuration options for Keycloak admin client.
   */
  constructor(options: KeycloakAdminOptions) {
    this.options = options;
    this.axios = axios.create({
      baseURL: options.baseUrl,
    });
    // To authenticate, call await keycloakAdmin.init(); after construction
  }

  /**
   * Call this method after constructing the client to authenticate and obtain a token.
   */
  async init(): Promise<void> {
    /**
     * Authenticates the client and retrieves an access token.
     * Must be called before using any API methods.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.authenticate();
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak authentication failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  // Example method stub for future REST API calls
  async getUsers(): Promise<any> {
    /**
     * Retrieves all users in the realm.
     * @returns List of users.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      return await this.axios.get(`/admin/realms/${this.options.realm}/users`, {
        headers: { Authorization: `Bearer ${this.accessToken}` },
      });
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak getUsers failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  // --- Authentication ---
  private async authenticate(): Promise<void> {
    /**
     * Internal method to authenticate and obtain an access token.
     * Uses either password or client credentials grant.
     */
    const { baseUrl, realm, clientId, clientSecret, username, password } =
      this.options;
    const params = new URLSearchParams();
    params.append("client_id", clientId);
    if (clientSecret) params.append("client_secret", clientSecret);
    if (username && password) {
      params.append("grant_type", "password");
      params.append("username", username);
      params.append("password", password);
    } else {
      params.append("grant_type", "client_credentials");
    }
    const tokenUrl = `${baseUrl}/realms/${realm}/protocol/openid-connect/token`;
    const response = await axios.post(tokenUrl, params, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    this.accessToken = response.data.access_token;
  }

  private async ensureAuthenticated(): Promise<void> {
    /**
     * Ensures the client is authenticated before making API calls.
     * Authenticates if no access token is present.
     */
    if (!this.accessToken) {
      await this.authenticate();
    }
  }

  // --- API Method Stubs ---
  async getUser(userId: string): Promise<any> {
    /**
     * Retrieves a user by their ID.
     * @param userId The ID of the user to retrieve.
     * @returns The user object.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      return await this.axios.get(
        `/admin/realms/${this.options.realm}/users/${userId}`,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak getUser failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  async createUser(user: KeycloakUser): Promise<any> {
    /**
     * Creates a new user in the realm.
     * @param user The user object to create.
     * @returns The created user object.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      return await this.axios.post(
        `/admin/realms/${this.options.realm}/users`,
        user,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak createUser failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  async updateUser(userId: string, user: KeycloakUser): Promise<any> {
    /**
     * Updates an existing user in the realm.
     * @param userId The ID of the user to update.
     * @param user The updated user object.
     * @returns The updated user object.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      return await this.axios.put(
        `/admin/realms/${this.options.realm}/users/${userId}`,
        user,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak updateUser failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  async deleteUser(userId: string): Promise<any> {
    /**
     * Deletes a user from the realm.
     * @param userId The ID of the user to delete.
     * @returns The response from Keycloak.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      return await this.axios.delete(
        `/admin/realms/${this.options.realm}/users/${userId}`,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak deleteUser failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  // Add similar methods for groups, roles, clients, realms, etc.
  async getGroups(): Promise<any> {
    /**
     * Retrieves all groups in the realm.
     * @returns List of groups.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      return await this.axios.get(
        `/admin/realms/${this.options.realm}/groups`,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak getGroups failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  async getRoles(): Promise<any> {
    /**
     * Retrieves all roles in the realm.
     * @returns List of roles.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      return await this.axios.get(`/admin/realms/${this.options.realm}/roles`, {
        headers: { Authorization: `Bearer ${this.accessToken}` },
      });
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak getRoles failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  async getClients(): Promise<any> {
    /**
     * Retrieves all clients in the realm.
     * @returns List of clients.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      return await this.axios.get(
        `/admin/realms/${this.options.realm}/clients`,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak getClients failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  async getClient(clientId: string): Promise<any> {
    /**
     * Retrieves a client by its ID.
     * @param clientId The ID of the client to retrieve.
     * @returns The client object.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      return await this.axios.get(
        `/admin/realms/${this.options.realm}/clients/${clientId}`,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak getClient failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  async createClient(client: KeycloakClient): Promise<any> {
    /**
     * Creates a new client in the realm.
     * @param client The client object to create.
     * @returns The created client object.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      return await this.axios.post(
        `/admin/realms/${this.options.realm}/clients`,
        client,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak createClient failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  async updateClient(clientId: string, client: KeycloakClient): Promise<any> {
    /**
     * Updates an existing client in the realm.
     * @param clientId The ID of the client to update.
     * @param client The updated client object.
     * @returns The updated client object.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      return await this.axios.put(
        `/admin/realms/${this.options.realm}/clients/${clientId}`,
        client,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak updateClient failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  async updateClientAttribute(
    clientId: string,
    attributes: Partial<KeycloakClientAttributes>
  ): Promise<any> {
    /**
     * Updates specific attributes of a client.
     * @param clientId The ID of the client to update.
     * @param attributes The attributes to update.
     * @returns The updated client object.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      // Get current client
      const clientRes = await this.getClient(clientId);
      const client = clientRes.data;
      // Merge attributes
      client.attributes = { ...client.attributes, ...attributes };
      return await this.axios.put(
        `/admin/realms/${this.options.realm}/clients/${clientId}`,
        client,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak updateClientAttribute failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  async updateClientAccessTokenLifespan(
    clientId: string,
    lifespanSeconds: number
  ): Promise<any> {
    /**
     * Updates the access token lifespan for a client.
     * @param clientId The ID of the client to update.
     * @param lifespanSeconds The new lifespan in seconds.
     * @returns The updated client object.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      // Get current client
      const clientRes = await this.getClient(clientId);
      const client = clientRes.data;
      // Update attribute
      client.attributes = {
        ...client.attributes,
        accessTokenLifespan: lifespanSeconds.toString(),
      };
      return await this.axios.put(
        `/admin/realms/${this.options.realm}/clients/${clientId}`,
        client,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak updateClientAccessTokenLifespan failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  async deleteClient(clientId: string): Promise<any> {
    /**
     * Deletes a client from the realm.
     * @param clientId The ID of the client to delete.
     * @returns The response from Keycloak.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      return await this.axios.delete(
        `/admin/realms/${this.options.realm}/clients/${clientId}`,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak deleteClient failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  // --- Additional User Operations ---
  async resetUserPassword(
    /**
     * Resets a user's password.
     * @param userId The ID of the user.
     * @param password The new password.
     * @param temporary Whether the password is temporary.
     * @returns The response from Keycloak.
     * @throws Error in JSON format with code, message, and stack.
     */
    userId: string,
    password: string,
    temporary = false
  ): Promise<any> {
    try {
      await this.ensureAuthenticated();
      const payload = {
        type: "password",
        value: password,
        temporary,
      };
      return await this.axios.put(
        `/admin/realms/${this.options.realm}/users/${userId}/reset-password`,
        payload,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak resetUserPassword failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  async sendVerifyEmail(userId: string): Promise<any> {
    /**
     * Sends a verification email to a user.
     * @param userId The ID of the user.
     * @returns The response from Keycloak.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      return await this.axios.put(
        `/admin/realms/${this.options.realm}/users/${userId}/send-verify-email`,
        {},
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak sendVerifyEmail failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  async getUserSessions(userId: string): Promise<any> {
    /**
     * Retrieves all sessions for a user.
     * @param userId The ID of the user.
     * @returns List of sessions.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      return await this.axios.get(
        `/admin/realms/${this.options.realm}/users/${userId}/sessions`,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak getUserSessions failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  async logoutUser(userId: string): Promise<any> {
    /**
     * Logs out a user from all sessions.
     * @param userId The ID of the user.
     * @returns The response from Keycloak.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      return await this.axios.post(
        `/admin/realms/${this.options.realm}/users/${userId}/logout`,
        {},
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak logoutUser failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }

  async getRealm(): Promise<any> {
    /**
     * Retrieves realm details.
     * @returns The realm object.
     * @throws Error in JSON format with code, message, and stack.
     */
    try {
      await this.ensureAuthenticated();
      return await this.axios.get(`/admin/realms/${this.options.realm}`, {
        headers: { Authorization: `Bearer ${this.accessToken}` },
      });
    } catch (err: any) {
      const error = {
        code: err?.response?.status || 500,
        message:
          err?.response?.data?.error_description ||
          err?.message ||
          "Keycloak getRealm failed",
        stack: err?.stack || JSON.stringify(err),
      };
      throw new Error(JSON.stringify(error));
    }
  }
}
