# frozen_string_literal: true

# Redmine - project management software
# Copyright (C) 2006-  Jean-Philippe Lang
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

require_relative '../../test_helper'

class Redmine::ApiTest::ApiAuditCredentialTest < Redmine::ApiTest::Base
  def teardown
    User.current = nil
    super
  end

  # Performs the request and returns the API audit data that the controller
  # attached to the process_action.action_controller notification
  def audit_data_for(method, path, **options)
    data = []
    callback = lambda {|event| data << event.payload[:redmine_api_audit]}
    ActiveSupport::Notifications.subscribed(callback, 'process_action.action_controller') do
      send(method, path, **options)
    end
    data.last
  end

  def create_personal_access_token(user=User.find(2))
    PersonalAccessToken.create!(:user => user, :name => 'Audit', :expiration_date => user.today + 30)
  end

  def create_oauth_token(user=User.find(2))
    application = Doorkeeper::Application.create!(:name => 'Audit app', :redirect_uri => 'https://example.net/callback',
                                                  :scopes => 'view_issues')
    Doorkeeper::AccessToken.create!(:application => application, :resource_owner_id => user.id,
                                    :scopes => 'view_issues', :expires_in => 3600)
  end

  # Asserts that the audit data does not contain the given secret
  def assert_no_secret(secret, data)
    assert_not_includes data.values.map(&:to_s).join, secret
  end

  def test_anonymous_api_request
    data = audit_data_for(:get, '/projects.json')
    assert_equal(
      {:auth_kind => 'none', :auth_failed => false, :user_id => nil, :switched_from_user_id => nil,
       :personal_access_token_id => nil, :oauth_application_id => nil,
       :http_method => 'GET', :path => '/projects.json', :ip => '127.0.0.1'},
      data
    )
  end

  def test_credential_should_be_none_when_rest_api_is_disabled
    with_settings :rest_api_enabled => '0' do
      data = audit_data_for(:get, '/projects.json', :headers => {'X-Redmine-API-Key' => User.find(2).api_key})
      assert_equal ['none', false, nil], data.values_at(:auth_kind, :auth_failed, :user_id)
    end
  end

  def test_credential_should_be_none_for_action_without_api_auth
    # ActivitiesController does not accept API authentication
    data = audit_data_for(:get, '/activity.json', :headers => {'X-Redmine-API-Key' => User.find(2).api_key})
    assert_equal ['none', false, nil], data.values_at(:auth_kind, :auth_failed, :user_id)
  end

  def test_html_request_should_not_be_audited
    assert_nil audit_data_for(:get, '/projects')
  end

  def test_legacy_api_key
    data = audit_data_for(:get, '/users/current.json', :headers => {'X-Redmine-API-Key' => User.find(2).api_key})
    assert_equal ['api_key', false, 2], data.values_at(:auth_kind, :auth_failed, :user_id)
    assert_no_secret User.find(2).api_key, data
  end

  def test_unknown_legacy_api_key
    data = audit_data_for(:get, '/users/current.json', :headers => {'X-Redmine-API-Key' => 'x' * 40})
    assert_response :unauthorized
    assert_equal ['api_key', true, nil], data.values_at(:auth_kind, :auth_failed, :user_id)
  end

  def test_personal_access_token_in_header
    token = create_personal_access_token
    data = audit_data_for(:get, '/users/current.json', :headers => {'X-Redmine-API-Key' => token.plaintext_token})
    assert_equal ['pat', false, 2, token.id],
                 data.values_at(:auth_kind, :auth_failed, :user_id, :personal_access_token_id)
    assert_no_secret token.plaintext_token, data
  end

  def test_personal_access_token_in_key_parameter_should_not_be_in_path
    token = create_personal_access_token
    data = audit_data_for(:get, "/users/current.json?key=#{token.plaintext_token}")
    assert_equal ['pat', token.id], data.values_at(:auth_kind, :personal_access_token_id)
    assert_equal '/users/current.json', data[:path]
    assert_no_secret token.plaintext_token, data
  end

  def test_personal_access_token_as_basic_username
    token = create_personal_access_token
    data = audit_data_for(:get, '/users/current.json', :headers => credentials(token.plaintext_token, 'X'))
    assert_equal ['pat', false, token.id], data.values_at(:auth_kind, :auth_failed, :personal_access_token_id)
    assert_no_secret token.plaintext_token, data
  end

  def test_expired_personal_access_token
    token = create_personal_access_token
    data =
      travel_to(token.expires_on + 1.second) do
        audit_data_for(:get, '/users/current.json', :headers => {'X-Redmine-API-Key' => token.plaintext_token})
      end
    assert_equal ['pat', true, nil, nil],
                 data.values_at(:auth_kind, :auth_failed, :user_id, :personal_access_token_id)
  end

  def test_basic_password
    data = audit_data_for(:get, '/users/current.json', :headers => credentials('jsmith', 'jsmith'))
    assert_equal ['basic', false, 2], data.values_at(:auth_kind, :auth_failed, :user_id)
  end

  def test_basic_wrong_password
    data = audit_data_for(:get, '/users/current.json', :headers => credentials('jsmith', 'wrong'))
    assert_equal ['basic', true, nil], data.values_at(:auth_kind, :auth_failed, :user_id)
  end

  def test_basic_password_blocked_by_twofa
    user = User.generate! do |u|
      u.password = 'my_password'
      u.update(:twofa_scheme => 'totp')
    end
    data = audit_data_for(:get, '/users/current.json', :headers => credentials(user.login, 'my_password'))
    assert_response :unauthorized
    assert_equal ['basic', true, nil], data.values_at(:auth_kind, :auth_failed, :user_id)
  end

  def test_basic_password_of_user_who_must_change_password
    user = User.find(2)
    user.update_column(:must_change_passwd, true)
    data = audit_data_for(:get, '/users/current.json', :headers => credentials('jsmith', 'jsmith'))
    assert_response :forbidden
    assert_equal ['basic', false, user.id], data.values_at(:auth_kind, :auth_failed, :user_id)
  end

  def test_legacy_api_key_as_basic_username
    data = audit_data_for(:get, '/users/current.json', :headers => credentials(User.find(2).api_key, 'X'))
    assert_equal ['api_key', false, 2], data.values_at(:auth_kind, :auth_failed, :user_id)
    assert_no_secret User.find(2).api_key, data
  end

  def test_oauth_token
    token = create_oauth_token
    data = audit_data_for(:get, '/users/current.json',
                          :headers => {'Authorization' => "Bearer #{token.plaintext_token}"})
    assert_equal ['oauth', false, 2, token.application_id],
                 data.values_at(:auth_kind, :auth_failed, :user_id, :oauth_application_id)
    assert_no_secret token.plaintext_token, data
  end

  def test_oauth_token_of_locked_user
    token = create_oauth_token
    User.find(2).lock!
    data = audit_data_for(:get, '/users/current.json',
                          :headers => {'Authorization' => "Bearer #{token.plaintext_token}"})
    # Pre-existing behaviour: the missing owner raises an error
    assert_response :internal_server_error
    assert_equal ['oauth', true, nil, token.application_id],
                 data.values_at(:auth_kind, :auth_failed, :user_id, :oauth_application_id)
  end

  def test_revoked_oauth_token
    token = create_oauth_token
    token.revoke
    data = audit_data_for(:get, '/users/current.json',
                          :headers => {'Authorization' => "Bearer #{token.plaintext_token}"})
    assert_response :unauthorized
    assert_equal ['oauth', true, nil, token.application_id],
                 data.values_at(:auth_kind, :auth_failed, :user_id, :oauth_application_id)
  end

  def test_unknown_oauth_token
    data = audit_data_for(:get, '/users/current.json', :headers => {'Authorization' => 'Bearer unknown'})
    assert_response :unauthorized
    assert_equal ['oauth', true, nil], data.values_at(:auth_kind, :auth_failed, :oauth_application_id)
  end

  def test_switch_user
    data = audit_data_for(:get, '/users/current.json',
                          :headers => {'X-Redmine-API-Key' => User.find(1).api_key,
                                       'X-Redmine-Switch-User' => 'jsmith'})
    assert_equal ['api_key', false, 2, 1],
                 data.values_at(:auth_kind, :auth_failed, :user_id, :switched_from_user_id)
  end

  def test_switch_user_with_personal_access_token
    token = create_personal_access_token(User.find(1))
    data = audit_data_for(:get, '/users/current.json',
                          :headers => {'X-Redmine-API-Key' => token.plaintext_token,
                                       'X-Redmine-Switch-User' => 'jsmith'})
    assert_equal ['pat', 2, 1, token.id],
                 data.values_at(:auth_kind, :user_id, :switched_from_user_id, :personal_access_token_id)
  end

  def test_malformed_json_body_should_be_audited
    data = audit_data_for(:post, '/issues.json', :params => '{bad',
                                                 :headers => {'CONTENT_TYPE' => 'application/json'})
    assert_response :bad_request
    assert_not_nil data
    assert_equal 'POST', data[:http_method]
  end

  def test_invalid_switch_user_should_not_be_an_authentication_failure
    data = audit_data_for(:get, '/users/current.json',
                          :headers => {'X-Redmine-API-Key' => User.find(1).api_key,
                                       'X-Redmine-Switch-User' => 'foobar'})
    assert_response :precondition_failed
    assert_equal ['api_key', false, 1, nil],
                 data.values_at(:auth_kind, :auth_failed, :user_id, :switched_from_user_id)
  end
end
