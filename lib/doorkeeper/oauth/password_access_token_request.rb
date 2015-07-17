module Doorkeeper
  module OAuth
    class PasswordAccessTokenRequest
      include Validations
      include OAuth::RequestConcern
      include OAuth::Helpers

      validate :client,         error: :invalid_client
      validate :resource_owner, error: :invalid_grant
      validate :scopes,         error: :invalid_scope

      attr_accessor :server, :resource_owner, :access_token
      attr_accessor :client

      # Deprecated :credentials accessor:
      attr_accessor :credentials
      deprecate :credentials

      def initialize(server, client, resource_owner, parameters = {})
        @server          = server
        @resource_owner  = resource_owner
        @client          = client
        @original_scopes = parameters[:scope]
      end

      private

      def before_successful_response
        find_or_create_access_token(client, resource_owner.id, scopes, server)
      end

      def validate_scopes
        return true unless @original_scopes.present?
        ScopeChecker.valid? @original_scopes, server.scopes, client.try(:scopes)
      end

      def validate_resource_owner
        !!resource_owner
      end

      def validate_client
        # Validate only if a client was given:
        if client.present?
          !!client
        else
          # No client given... but resource_owner given. Should issue token.
          true
        end
      end
    end
  end
end
