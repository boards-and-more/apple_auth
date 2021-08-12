# frozen_string_literal: true

module AppleAuth
  module Conditions
    class AudCondition
      def initialize(jwt)
        @aud = jwt['aud']
      end

      def validate!(config: nil)
        if config.present?
          return true if @aud == config.apple_client_id
        else
          return true if @aud == AppleAuth.config.apple_client_id
        end

        raise JWTValidationError, 'jwt_aud is different to apple_client_id'
      end
    end
  end
end
