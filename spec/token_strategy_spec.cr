require "./spec_helper"

module Authly
  class ArrayScopeClaimsProvider
    include ClaimsProvider

    def enrich_access_token(payload : JWTPayload, client_id : String, sub : String, scope : String) : JWTPayload
      payload["scope"] = scope.split(" ")
      payload
    end
  end

  describe "Token Strategy" do
    client_id = "1"
    scope = "read"

    describe "JWT Token Strategy" do
      it "generates JWT access tokens" do
        # Ensure JWT strategy is active
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :jwt

        token = AccessToken.new(client_id, scope)

        # JWT tokens should be decodable
        decoded, _header = Authly.jwt_decode(token.access_token)
        decoded["cid"].should eq client_id
        decoded["scope"].should eq scope

        Authly.config.token_strategy = original_strategy
      end

      it "generates JWT refresh tokens" do
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :jwt

        token = AccessToken.new(client_id, scope)

        # JWT refresh tokens should be decodable
        decoded, _header = Authly.jwt_decode(token.refresh_token)
        decoded["sub"].should eq client_id

        Authly.config.token_strategy = original_strategy
      end

      it "validates JWT tokens correctly" do
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :jwt

        token = AccessToken.new(client_id, scope)
        Authly.valid?(token.access_token).should be_true

        Authly.config.token_strategy = original_strategy
      end

      it "revokes JWT tokens" do
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :jwt

        token = AccessToken.new(client_id, scope)
        Authly.revoke(token.access_token)
        Authly.revoked?(token.access_token).should be_true

        Authly.config.token_strategy = original_strategy
      end

      it "introspects JWT tokens" do
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :jwt

        token = AccessToken.new(client_id, scope)
        result = Authly.introspect(token.access_token)

        result["active"].should be_true
        result["cid"].should eq client_id
        result["scope"].should eq scope

        Authly.config.token_strategy = original_strategy
      end

      it "introspects JWT tokens with array scopes" do
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :jwt

        original_provider = Authly.config.claims_provider
        Authly.config.claims_provider = ArrayScopeClaimsProvider.new

        token = AccessToken.new(client_id, "read write")
        result = Authly.introspect(token.access_token)

        result["active"].should be_true
        result["scope"].should eq "read write" # Should be joined back to string

        Authly.config.claims_provider = original_provider
        Authly.config.token_strategy = original_strategy
      end

      it "introspects JWT tokens using aud when cid is missing" do
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :jwt

        # Create a custom token without cid but with aud
        payload = {
          "sub"   => "sub_123",
          "iss"   => Authly.config.issuer,
          "aud"   => client_id,
          "iat"   => Time.utc.to_unix,
          "exp"   => 1.hour.from_now.to_unix,
          "scope" => scope,
          "jti"   => Random::Secure.hex(32),
        }
        custom_token = Authly.jwt_encode(payload)

        result = Authly.introspect(custom_token)

        result["active"].should be_true
        result["cid"].should eq client_id # Should fall back to aud

        Authly.config.token_strategy = original_strategy
      end
    end

    describe "Opaque Token Strategy" do
      it "generates opaque access tokens" do
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :opaque

        token = AccessToken.new(client_id, scope)

        # Opaque tokens should not be JWTs (should be random hex)
        token.access_token.should match(/^[a-f0-9]{64}$/)

        # Should not be decodable as JWT
        expect_raises(JWT::DecodeError) do
          Authly.jwt_decode(token.access_token)
        end

        Authly.config.token_strategy = original_strategy
      end

      it "stores opaque token metadata" do
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :opaque

        token = AccessToken.new(client_id, scope)

        # Metadata should be stored in token_store using access_token as key
        metadata = Authly.config.token_store.fetch(token.access_token)
        metadata.should_not be_nil
        metadata["cid"].to_s.should eq client_id
        metadata["scope"].to_s.should eq scope

        Authly.config.token_strategy = original_strategy
      end

      it "validates opaque tokens correctly" do
        original_strategy = Authly.config.token_strategy
        original_store = Authly.config.token_store
        Authly.config.token_strategy = :opaque
        Authly.config.token_store = InMemoryStore.new

        token = AccessToken.new(client_id, scope)

        # Token should be valid
        manager = TokenManager.new(token_manager: OpaqueToken.new)
        manager.valid?(token.access_token).should be_true

        Authly.config.token_strategy = original_strategy
        Authly.config.token_store = original_store
      end

      it "revokes opaque tokens" do
        original_strategy = Authly.config.token_strategy
        original_store = Authly.config.token_store
        Authly.config.token_strategy = :opaque
        Authly.config.token_store = InMemoryStore.new

        token = AccessToken.new(client_id, scope)

        manager = TokenManager.new(token_manager: OpaqueToken.new)
        manager.revoke(token.access_token)
        manager.revoked?(token.access_token).should be_true

        Authly.config.token_strategy = original_strategy
        Authly.config.token_store = original_store
      end

      it "introspects opaque tokens" do
        original_strategy = Authly.config.token_strategy
        original_store = Authly.config.token_store
        Authly.config.token_strategy = :opaque
        Authly.config.token_store = InMemoryStore.new

        token = AccessToken.new(client_id, scope)

        manager = TokenManager.new(token_manager: OpaqueToken.new)
        result = manager.introspect(token.access_token)

        result["active"].should be_true
        result["cid"].should eq client_id
        result["scope"].should eq scope

        Authly.config.token_strategy = original_strategy
        Authly.config.token_store = original_store
      end
    end
  end
end
