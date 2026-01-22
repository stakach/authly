module Authly
  struct AccessToken
    include JSON::Serializable
    ACCESS_TTL  = Authly.config.access_ttl
    REFRESH_TTL = Authly.config.refresh_ttl

    # Subject (user ID or client ID)
    @[JSON::Field(ignore_deserialize: true)]
    getter sub : String = ""
    # JWT ID for tracking/revocation
    getter jti : String
    getter access_token : String
    getter token_type : String = "Bearer"
    getter scope : String
    getter expires_in : Int64 = ACCESS_TTL.from_now.to_unix
    getter? revoked : Bool = false
    @[JSON::Field(emit_null: false)]
    getter refresh_token : String
    @[JSON::Field(emit_null: false)]
    getter id_token : String? = nil
    @[JSON::Field(ignore: true)]
    getter client_id : String

    def self.jwt(client_id, scope, id_token)
      new(client_id, scope, id_token).to_json
    end

    # Initialize with optional user_id for password grant flow
    #
    # @param client_id - The OAuth client ID
    # @param scope - Space-separated scopes
    # @param id_token - Optional OpenID Connect ID token
    # @param cert_thumbprint - Optional mTLS certificate thumbprint
    # @param user_id - Optional user ID (from password grant or authorization code)
    def initialize(@client_id : String, @scope : String, @id_token : String? = nil, cert_thumbprint : String? = nil, user_id : String? = nil)
      @jti = Random::Secure.hex(32)
      # Use provided user_id if available, otherwise generate random identifier
      @sub = user_id || Random::Secure.hex(32)

      generator = TokenGeneratorFactory.create
      @access_token = generator.generate_access_token(@client_id, @scope, @sub, @jti, cert_thumbprint)

      refresh_jti = Random::Secure.hex(32)
      @refresh_token = generator.generate_refresh_token(@client_id, refresh_jti)

      # Store metadata for opaque tokens (use access_token as key)
      expires_at = ACCESS_TTL.from_now
      if Authly.config.token_strategy == :opaque
        access_payload = {} of String => (String | Int64 | Bool | Float64)
        access_payload["cid"] = @client_id
        access_payload["scope"] = @scope
        access_payload["sub"] = @sub
        access_payload["iat"] = Time.utc.to_unix
        access_payload["exp"] = expires_at.to_unix
        access_payload["token_type"] = "access_token"
        access_payload["jti"] = @jti

        # Add certificate thumbprint if provided
        if cert_thumbprint
          access_payload["cnf"] = cert_thumbprint
        end

        Authly.config.token_store.store(@access_token, access_payload)

        # Store refresh token metadata for opaque tokens
        refresh_payload = {} of String => (String | Int64 | Bool | Float64)
        refresh_payload["sub"] = @client_id
        refresh_payload["iat"] = Time.utc.to_unix
        refresh_payload["exp"] = REFRESH_TTL.from_now.to_unix
        refresh_payload["token_type"] = "refresh_token"
        refresh_payload["jti"] = refresh_jti
        Authly.config.token_store.store(@refresh_token, refresh_payload)
      else
        # For JWT tokens, optionally store metadata if persistence is enabled
        generator.store_token_metadata(@jti, @client_id, @scope, @sub, expires_at, cert_thumbprint)
      end
    end
  end
end
