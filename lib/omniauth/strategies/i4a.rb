require 'omniauth-oauth2'
require 'cgi'

module OmniAuth
  module Strategies
    class I4a < OmniAuth::Strategies::OAuth2
      option :client_options, {
        site: 'https://i4a.org',
        meeting_groups: false,
        enable_credits: false,
        account_id: 'MUST BE SET',
        svu_account_id: 'MUST BE SET',
        authorize_url: '/custom/bluesky.cfm',
        authenticate_url: '/i4a/api/authenticate',
        user_info_url: '/i4a/api/json/view.ams_contactInformation_memberType',
        contact_type_url: '/i4a/api/json/view.ams_contactType_extended',
        meeting_info_url: '/i4a/api/json/view.custom_meeting_attendees_for_api',
        meeting_groups_url: '/i4a/api/json/view.ams_tracking_invoice',
        username: 'MUST BE SET',
        password: 'MUST BE SET',
        authentication_token: '12345678-1234-1234-1234567890123456'
      }

      uid { user_data['id'] }

      name { 'i4a' }

      info do
        params = {
          'first_name' => user_data['firstname'],
          'last_name' => user_data['lastname'],
          'email' => user_data['email'],
          'username' => user_data['id'],
          'is_active_member' => is_active_member,
          'member_type' => user_data['membertype'],
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
        if member_id
          response = authenticate
          if response.success?
            self.access_token = { 'token' => JSON.parse(response.body)['authkey'] }
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
        hash = AuthHash.new('provider' => name, 'uid' => uid)
        hash.info = info
        hash.credentials = self.access_token
        hash
      end

      private

      def fetch_data(url)
        response = Typhoeus.get url
        if response.success?
          data = JSON.parse response.body
          flat_data = flatten_data data['COLUMNS'], data['DATA']
        else
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

      def contact_type_data_url
        "#{options.client_options.site}#{options.client_options.contact_type_url}/contactid=#{member_id}/#{token}"
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
        return false if user_data['membertype'].nil? ||
          user_data['membertype'].downcase == 'null' ||
          user_data['paidthru'].downcase == 'null' ||
          !(Date.parse(user_data['paidthru']) >= (Date.today - 60.days))
        true
        rescue
          return false
      end

      def member_id
        request.params['memberID']
      end

      def svu_client?
        options.client_options.account_id.to_i == options.client_options.svu_account_id.to_i
      end

      def svu_custom_params
        { 'ardms_number' => user_data['c_user_ardms'], 'cci_number' => user_data['c_user_ardms'] }
      end
    end
  end
end
