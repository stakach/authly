require "../spec_helper"

module Authly
  cid, secret, username, password = "1", "secret", "username", "password"

  describe Password do
    it "returns true when authorized" do
      password_authorization = Password.new(
        client_id: cid, client_secret: secret, username: username, password: password
      )

      password_authorization.authorized?.should be_truthy
    end

    it "stores user_id after successful authorization" do
      password_authorization = Password.new(
        client_id: cid, client_secret: secret, username: username, password: password
      )

      password_authorization.authorized?
      password_authorization.user_id.should_not be_nil
    end

    it "raises error for invalid client credentials" do
      invalid_auth = Password.new(
        client_id: cid, client_secret: "bad secret", username: username, password: password
      )

      expect_raises Error, ERROR_MSG[:unauthorized_client] do
        invalid_auth.authorized?
      end
    end

    it "raises error for invalid owner credentials" do
      invalid_owner = Password.new(
        client_id: cid, client_secret: secret, username: username, password: "bad password"
      )

      expect_raises Error, ERROR_MSG[:owner_credentials] do
        invalid_owner.authorized?
      end
    end

    it "has nil user_id before authorization" do
      password_authorization = Password.new(
        client_id: cid, client_secret: secret, username: username, password: password
      )

      password_authorization.user_id.should be_nil
    end
  end
end
