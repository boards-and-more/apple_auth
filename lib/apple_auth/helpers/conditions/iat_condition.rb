# frozen_string_literal: true

module AppleAuth
  module Conditions
    class IatCondition
      def initialize(jwt)
        @iat = jwt['iat'].to_i
      end

      def validate!(config: nil)
        return true if @iat <= Time.now.to_i

        raise JWTValidationError, 'jwt_iat is greater than now'
      end
    end
  end
end
