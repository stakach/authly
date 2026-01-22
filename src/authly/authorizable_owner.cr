module Authly
  # Interface for authenticating resource owners (users)
  #
  # Implement this module to provide user authentication for password grant
  # and other flows that require owner credentials.
  module AuthorizableOwner
    # Authenticate user by username/password
    #
    # @param username - The username (typically email)
    # @param password - The password to verify
    # @return user_id on success, nil on failure
    #
    # Example:
    # ```
    # class MyOwner
    #   include Authly::AuthorizableOwner
    #
    #   def authorized?(username : String, password : String) : String?
    #     user = User.where(email: username.downcase).first?
    #     return nil unless user&.verify_password(password)
    #     user.id.to_s
    #   end
    # end
    # ```
    abstract def authorized?(username : String, password : String) : String?

    # Generate ID token claims for a user
    #
    # @param user_id - The user's unique identifier
    # @return Hash of claims to include in the ID token
    abstract def id_token(user_id : String) : Hash(String, String | Int64)
  end
end
