require "./spec_helper"

module Authly
  class TestClaimsProvider
    include ClaimsProvider

    def enrich_access_token(payload : JWTPayload, client_id : String, sub : String, scope : String) : JWTPayload
      payload["custom_claim"] = "custom_value"
      payload["roles"] = ["admin", "user"]
      payload
    end
  end

  describe ClaimsProvider do
    describe DefaultClaimsProvider do
      it "returns the payload unchanged" do
        provider = DefaultClaimsProvider.new
        payload = {
          "sub"   => "user_123",
          "iss"   => "test_issuer",
          "scope" => "read write",
        } of String => ClaimValue

        result = provider.enrich_access_token(payload, "client_123", "user_123", "read write")

        result.should eq payload
      end

      it "does not modify any claims" do
        provider = DefaultClaimsProvider.new
        payload = {
          "sub" => "user_123",
          "cid" => "client_123",
          "exp" => 12345_i64,
        } of String => ClaimValue

        result = provider.enrich_access_token(payload, "client_123", "user_123", "read")

        result["sub"].should eq "user_123"
        result["cid"].should eq "client_123"
        result["exp"].should eq 12345_i64
      end
    end
  end

  describe "Custom ClaimsProvider" do
    it "can add custom claims to payload" do
      provider = TestClaimsProvider.new
      payload = {
        "sub" => "user_123",
        "iss" => "test_issuer",
      } of String => ClaimValue

      result = provider.enrich_access_token(payload, "client_123", "user_123", "read")

      result["custom_claim"].should eq "custom_value"
      result["roles"].should eq ["admin", "user"]
    end

    it "preserves existing claims" do
      provider = TestClaimsProvider.new
      payload = {
        "sub"   => "user_123",
        "scope" => "read write",
      } of String => ClaimValue

      result = provider.enrich_access_token(payload, "client_123", "user_123", "read write")

      result["sub"].should eq "user_123"
      result["scope"].should eq "read write"
    end

    it "can be configured in Authly.config" do
      original_provider = Authly.config.claims_provider
      test_provider = TestClaimsProvider.new

      Authly.config.claims_provider = test_provider
      Authly.config.claims_provider.should be_a(TestClaimsProvider)

      Authly.config.claims_provider = original_provider
    end
  end
end
