require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class I4a < OmniAuth::Strategies::OAuth2
      option :client_options, {
        site: 'https://i4a.org',
        authorize_url: '/custom/bluesky.cfm',
        authenticate_url: '/i4a/api/authenticate',
        user_info_url: '/i4a/api/json/membership.contact',
        username: 'MUST BE SET',
        password: 'MUST BE SET',
        authentication_token: '12345678-1234-1234-1234567890123456'
      }

      uid { raw_info['RECORD']['id'] }

      name {'bcom'}

      info do
        {
          first_name: raw_info['RECORD']['firstName'],
          last_name: raw_info['RECORD']['lastName'],
          email: raw_info['RECORD']['email']
        }
      end

      extra do
        { :raw_info => raw_info }
      end

      def creds
        self.access_token
      end

      def request_phase
        slug = session['omniauth.params']['origin'].gsub(/\//,"")
        redirect client.auth_code.authorize_url({:blueskyReturnUrl => callback_url + "?slug=#{slug}"})
      end

      def callback_phase
        if member_id
          response = authenticate

          if response.success?
            self.access_token = {
              :token => JSON.parse(response.body)['authkey']
            }

            self.env['omniauth.auth'] = auth_hash
            self.env['omniauth.origin'] = '/' + request.params['slug']
            call_app!
          else
            fail!(:invalid_credentials)
          end
        else
          fail!(:invalid_credentials)
        end
      end

      def auth_hash
        hash = AuthHash.new(:provider => name, :uid => uid)
        hash.info = info
        hash.credentials = creds
        hash
      end

      def raw_info
        @raw_info ||= get_user_info(access_token[:token], member_id)
      end

      private

      def authenticate
        Typhoeus.get("#{authenticate_url}/#{username}/#{password}/#{authentication_token}")
      end

      def authenticate_url
        "#{options.client_options.site}#{options.client_options.authenticate_url}"
      end

      def authentication_token
        options.client_options.authentication_token
      end

      def get_user_info(token, member_id)
        response = Typhoeus.get("#{user_info_url}/#{member_id}/#{token}")

        if response.success?
          JSON.parse(response.body)
        else
          nil
        end
      end

      def member_id
        request.params['memberID']
      end

      def password
        options.client_options.password
      end

      def username
        options.client_options.username
      end

      def user_info_url
        "#{options.client_options.site}#{options.client_options.user_info_url}"
      end
    end
  end
end
