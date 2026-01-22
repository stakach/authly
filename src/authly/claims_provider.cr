module Authly
  # Type alias for JWT payload values
  alias ClaimValue = String | Int64 | Bool | Array(String) | Hash(String, String) | Hash(String, String | Int64 | Array(String))
  alias JWTPayload = Hash(String, ClaimValue)

  # Interface for adding custom claims to JWT access tokens
  #
  # Implement this module to inject application-specific claims into
  # JWT tokens during generation. This is useful for adding user metadata,
  # roles, permissions, or any other custom data.
  #
  # Example:
  # ```
  # class MyClaimsProvider
  #   include Authly::ClaimsProvider
  #
  #   def enrich_access_token(payload, client_id, sub, scope)
  #     user = User.find?(sub)
  #     if user
  #       payload["name"] = user.name
  #       payload["email"] = user.email
  #       payload["roles"] = user.roles
  #     end
  #     payload
  #   end
  # end
  #
  # Authly.configure do |config|
  #   config.claims_provider = MyClaimsProvider.new
  # end
  # ```
  module ClaimsProvider
    # Called during token generation to enrich the JWT payload
    #
    # @param payload - The base JWT payload with standard claims (sub, iss, iat, exp, etc.)
    # @param client_id - The OAuth client ID requesting the token
    # @param sub - The subject (typically user ID)
    # @param scope - Space-separated list of granted scopes
    # @return Modified payload hash with additional claims
    abstract def enrich_access_token(
      payload : JWTPayload,
      client_id : String,
      sub : String,
      scope : String,
    ) : JWTPayload
  end

  # Default no-op implementation that passes through the payload unchanged
  class DefaultClaimsProvider
    include ClaimsProvider

    def enrich_access_token(payload, client_id, sub, scope) : JWTPayload
      payload
    end
  end
end
