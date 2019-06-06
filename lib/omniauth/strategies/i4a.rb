require 'omniauth-oauth2'
require 'cgi'

module OmniAuth
  module Strategies
    class I4a < OmniAuth::Strategies::OAuth2
      option :client_options, {
        site: 'https://i4a.org',
        meeting_groups: false,
        enable_credits: false,
        enable_corp_member_type_sync: false,
        account_id: 'MUST BE SET',
        svu_account_id: 'MUST BE SET',
        authorize_url: '/custom/bluesky.cfm',
        authenticate_url: '/i4a/api/authenticate',
        user_info_url: '/i4a/api/json/view.ams_contactInformation_memberType',
        contact_type_url: '/i4a/api/json/view.ams_contactType_extended',
        contact_corp_type_url: '/i4a/api/json/view.ams_contactInformation_corptype',
        meeting_info_url: '/i4a/api/json/view.custom_meeting_attendees_for_api',
        meeting_groups_url: '/i4a/api/json/view.ams_tracking_invoice',
        username: 'MUST BE SET',
        password: 'MUST BE SET',
        authentication_token: '12345678-1234-1234-1234567890123456'
      }

      option :app_options, { app_event_id: nil }

      uid { user_data['id'] }

      name { 'i4a' }

      info do
        params = {
          'first_name' => user_data['firstname'],
          'last_name' => user_data['lastname'],
          'email' => user_data['email'],
          'username' => user_data['id'],
          'is_active_member' => is_active_member,
          'member_type' => member_type,
          'contact_id' => user_data['contactid'],
          'date_joined' => user_data['datejoined'],
          'date_renewed' => user_data['daterenewed'],
          'paid_thru' => user_data['paidthru'],
          'contact_type_data' => contact_type_data,
          'meeting_attendance_data' => meeting_attendance_data,
          'meeting_groups_data' => meeting_groups_data
        }
        params.merge!(svu_custom_params) if svu_client?
        params
      end

      def request_phase
        slug = session['omniauth.params']['origin'].gsub(/\//,"")
        redirect client.auth_code.authorize_url({:blueskyReturnUrl => callback_url + "?slug=#{slug}"})
      end

      def callback_phase
        return fail!(:invalid_credentials) unless member_id

        @app_event = prepare_app_event
        response = authenticate
        response_log = "#{provider_name} Authentication Response (code: #{response.code}): \n#{response.body}"

        if response.success?
          @app_event.logs.create(level: 'info', text: response_log)

          self.access_token = { 'token' => JSON.parse(response.body)['authkey'] }
          self.env['omniauth.auth'] = auth_hash
          self.env['omniauth.origin'] = '/' + request.params['slug']
          self.env['omniauth.redirect_url'] = request.params['redirecturl'].presence
          self.env['omniauth.app_event_id'] = @app_event.id
          finalize_app_event

          call_app!
        else
          @app_event.logs.create(level: 'error', text: response_log)
          @app_event.fail!

          fail!(:invalid_credentials)
        end
      end

      def auth_hash
        hash = AuthHash.new('provider' => name, 'uid' => uid)
        hash.info = info
        hash.credentials = self.access_token
        hash
      end

      private

      def fetch_data(url)
        request_log = "#{provider_name} Authentication Request:\nGET #{url}, params: { token: #{Provider::SECURITY_MASK} }"
        @app_event.logs.create(level: 'info', text: request_log)

        response = Typhoeus.get url
        response_log = "#{provider_name} Authentication Response (code: #{response.code}): \n#{response.body}"


        if response.success?
          @app_event.logs.create(level: 'info', text: response_log)

          data = JSON.parse response.body
          flatten_data(data['COLUMNS'], data['DATA'])
        else
          @app_event.logs.create(level: 'error', text: response_log)
          @app_event.fail!

          nil
        end
      end

      def fetch_user_data
        fetch_data(user_data_url)[0]
      end

      def flatten_data(columns, data)
        if data[0].is_a? Array
          return data.map! { |row| flatten_data(columns, row) }
        end
        flat_data = {}
        data.each_with_index do |val, idx|
          flat_data[columns[idx].downcase] = val.to_s.strip
        end
        flat_data
      end

      # Authentication related methods

      def authenticate
        Typhoeus.get("#{authenticate_url}/#{options.client_options.username}/#{options.client_options.password}/#{authentication_token}")
      end

      def authenticate_url
        "#{options.client_options.site}#{options.client_options.authenticate_url}"
      end

      def authentication_token
        options.client_options.authentication_token
      end

      def token
        access_token['token']
      end

      # Contact Type related methods

      def contact_type_data
        return [] unless options.client_options.enable_credits
        @contact_type_data ||= fetch_data(contact_type_data_url)
      end

      def contact_corp_type_data
        return [] unless options.client_options.enable_corp_member_type_sync
        @contact_corp_type_data ||= fetch_data(contact_corp_type_data_url)
      end

      def contact_type_data_url
        "#{options.client_options.site}#{options.client_options.contact_type_url}/contactid=#{member_id}/#{token}"
      end

      def contact_corp_type_data_url
        "#{options.client_options.site}#{options.client_options.contact_corp_type_url}/contactid=#{member_id}/#{token}"
      end

      # Meeting Attendance related methods

      def meeting_attendance_data
        return [] unless options.client_options.enable_credits
        @meeting_attendance_data ||= fetch_data(meeting_attendance_data_url)
      end

      def meeting_attendance_data_url
        "#{options.client_options.site}#{options.client_options.meeting_info_url}/contactid=#{member_id}/#{token}"
      end

      # Meeting Group related methods

      def meeting_groups_data
        return [] unless options.client_options.meeting_groups
        @meeting_groups ||= fetch_data(meeting_groups_url)
      end

      def meeting_groups_url
        "#{options.client_options.site}#{options.client_options.meeting_groups_url}/contactid=#{member_id}/#{token}"
      end

      # User related methods

      def user_data
        @user_data ||= fetch_user_data
      end

      def user_data_url
        "#{options.client_options.site}#{options.client_options.user_info_url}/contactid=#{member_id}/#{token}"
      end

      def is_active_member
        return false if member_type.nil? ||
          member_type.downcase == 'null' ||
          membership_expiration.downcase == 'null' ||
          (Date.parse(expiration) < (Date.today - 60.days))
        true
        rescue
          return false
      end

      def member_type
        @member_type ||= if options.client_options.enable_corp_member_type_sync
          contact_corp_type_data['corptype']
        else
          user_data['membertype']
        end
      end

      def membership_expiration
        @membership_expiration ||= if options.client_options.enable_corp_member_type_sync
          contact_corp_type_data['corpexpiration']
        else
          user_data['paidthru']
        end
      end

      def member_id
        request.params['memberID']
      end

      def svu_client?
        options.client_options.account_id.to_i == options.client_options.svu_account_id.to_i
      end

      def svu_custom_params
        { 'ardms_number' => user_data['c_user_ardms'], 'cci_number' => user_data['c_user_cci'] }
      end

      # App Event methods

      def provider_name
        options.name
      end

      def prepare_app_event
        account = Account.find(options.client_options.account_id)
        account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')
      end

      def finalize_app_event
        app_event_data = {
          user_info: {
            uid: info['username'],
            first_name: info['first_name'],
            last_name: info['last_name'],
            email: info['email']
          }
        }

        @app_event.update(raw_data: app_event_data)
      end
    end
  end
end
