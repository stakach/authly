module Authly
  class Password
    include GrantStrategy
    getter client_id : String,
      client_secret : String,
      username : String,
      password : String

    # User ID from successful authentication (available after authorized? is called)
    getter user_id : String?

    def initialize(@client_id, @client_secret, @username, @password)
      @user_id = nil
    end

    def authorized? : Bool
      raise Error.unauthorized_client unless client_authorized?
      raise Error.unauthorized_client unless grant_type_authorized?

      # authorized? now returns user_id (String?) instead of Bool
      @user_id = Authly.owners.authorized?(username, password)
      raise Error.owner_credentials unless @user_id

      true
    end

    private def client_authorized?
      Authly.clients.authorized?(client_id, client_secret)
    end

    private def grant_type_authorized?
      Authly.clients.allowed_grant_type?(client_id, "password")
    end
  end
end
