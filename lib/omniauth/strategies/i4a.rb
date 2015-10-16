require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class I4a < OmniAuth::Strategies::OAuth2
      option :client_options, {
        site: 'https://i4a.org',
        account_id: 'MUST BE SET',
        svu_account_id: 'MUST BE SET',
        authorize_url: '/custom/bluesky.cfm',
        authenticate_url: '/i4a/api/authenticate',
        user_info_url: '/i4a/api/json/view.ams_contactInformation_memberType',
        username: 'MUST BE SET',
        password: 'MUST BE SET',
        authentication_token: '12345678-1234-1234-1234567890123456'
      }

      uid { member_data[member_columns.find_index('ID')] }

      name {'i4a'}

      info do
        params = {
          first_name: member_data[member_columns.find_index('FIRSTNAME')],
          last_name: member_data[member_columns.find_index('LASTNAME')],
          email: trim_whitespaces(member_data[member_columns.find_index('EMAIL')]),
          username: trim_whitespaces(member_data[member_columns.find_index('ID')]),
          is_active_member: is_active_member,
          member_type: member_type
        }
        params.merge!(svu_custom_params) if svu_client?
        params
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
        response = Typhoeus.get("#{user_info_url}/contactid=#{member_id}/#{token}")

        if response.success?
          JSON.parse(response.body)
        else
          nil
        end
      end

      def is_active_member
        return false if member_data[member_columns.find_index('MEMBERTYPE')].nil? ||
          member_data[member_columns.find_index('MEMBERTYPE')].downcase == 'null' ||
          member_data[member_columns.find_index('PAIDTHRU')].downcase == 'null' ||
          !(Date.parse(member_data[member_columns.find_index('PAIDTHRU')]) >= (Date.today - 60.days))
        true
      end

      def member_columns
        raw_info['COLUMNS']
      end

      def member_data
        @member_data ||= raw_info['DATA'].flatten
      end

      def member_id
        request.params['memberID']
      end

      def member_type
        member_data[member_columns.find_index('MEMBERTYPE')]
      end

      def password
        options.client_options.password
      end

      def trim_whitespaces(data)
        data.strip
      end

      def svu_client?
        options.client_options.account_id.to_i == options.client_options.svu_account_id.to_i
      end

      def svu_custom_params
        { ardms_number: user_ardms_number, cci_number: user_cci_number }
      end

      def username
        options.client_options.username
      end

      def user_info_url
        "#{options.client_options.site}#{options.client_options.user_info_url}"
      end

      def user_ardms_number
        member_data[member_columns.find_index('C_USER_ARDMS')]
      end

      def user_cci_number
        member_data[member_columns.find_index('C_USER_CCI')]
      end
    end
  end
end
