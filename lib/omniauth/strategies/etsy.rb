# frozen_string_literal: true

module OmniAuth
  module Strategies
    # OmniAuth strategy for Etsy
    class Etsy < OmniAuth::Strategies::OAuth2
      option :name, :etsy
      option :pkce, true
      option :callback_url

      option :setup, lambda { |env|
        strategy = env&.dig('omniauth.strategy')
        return unless strategy

        etsy_auth_params = strategy.session['etsy.omniauth_params'] ||
          strategy.session['omniauth.params'] ||
          strategy.request.params

        etsy_auth_params = etsy_auth_params&.with_indifferent_access

        strategy.options[:authorize_params] = etsy_auth_params
        strategy.options[:token_params] = { client_id: strategy.options['client_id'] }
      }

      uid { user_credentials['user_id'] }
      credentials { user_credentials }

      def setup_phase
        options.scope = preprocessed_scopes
        options.client_options.merge!(client_options)
        super
      end

      def callback_url
        options[:callback_url] || full_host + script_name + callback_path
      end

      private

      def user_credentials
        self.class.superclass.credentials_stack(self).first.merge(
          'expires_in' => access_token.expires_in.to_i,
          'user_id' => access_token.token.split('.').first
        )
      end

      def preprocessed_scopes
        Array(options.scope).join(' ')
      end

      def client_options
        {
          site: 'https://api.etsy.com',
          token_url: 'https://api.etsy.com/v3/public/oauth/token',
          authorize_url: 'https://www.etsy.com/oauth/connect',
          auth_scheme: :request_body
        }
      end
    end
  end
end
