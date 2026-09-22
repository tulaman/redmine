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

class Redmine::ApiTest::PersonalAccessTokensTest < Redmine::ApiTest::Base
  def setup
    super
    @user = User.find(2)
    @token = PersonalAccessToken.create!(:user => @user, :name => 'CI', :expiration_date => @user.today + 30)
    @plaintext = @token.plaintext_token
  end

  def teardown
    User.current = nil
    super
  end

  def test_should_authenticate_with_header
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => @plaintext}
    assert_response :ok
    assert_equal 'jsmith', response.parsed_body['user']['login']
  end

  def test_should_authenticate_with_key_parameter
    get "/users/current.json?key=#{@plaintext}"
    assert_response :ok
    assert_equal 'jsmith', response.parsed_body['user']['login']
  end

  def test_should_authenticate_with_http_basic_username
    get '/users/current.json', :headers => credentials(@plaintext, 'X')
    assert_response :ok
    assert_equal 'jsmith', response.parsed_body['user']['login']
  end

  def test_should_authenticate_xml_requests
    get '/users/current.xml', :headers => {'X-Redmine-API-Key' => @plaintext}
    assert_response :ok
    assert_select 'user>login', :text => 'jsmith'
  end

  def test_should_deny_expired_token
    travel_to @token.expires_on + 1.second do
      get '/users/current.json', :headers => {'X-Redmine-API-Key' => @plaintext}
    end
    assert_response :unauthorized
    assert response.headers.has_key?('WWW-Authenticate')
  end

  def test_should_deny_deleted_token
    @token.destroy
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => @plaintext}
    assert_response :unauthorized
  end

  def test_should_deny_token_of_locked_user
    @user.lock!
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => @plaintext}
    assert_response :unauthorized
  end

  def test_should_accept_token_again_after_user_is_unlocked
    @user.lock!
    @user.activate!
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => @plaintext}
    assert_response :ok
  end

  def test_should_deny_unknown_token
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => 'redmine_pat_' + ('x' * 40)}
    assert_response :unauthorized
  end

  def test_should_deny_token_when_rest_api_is_disabled
    with_settings :rest_api_enabled => '0' do
      get '/users/current.json', :headers => {'X-Redmine-API-Key' => @plaintext}
    end
    assert_response :forbidden
  end

  def test_rejected_token_should_not_fall_back_to_legacy_api_key
    User.expects(:find_by_api_key).never
    @token.destroy
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => @plaintext}
    assert_response :unauthorized
  end

  def test_legacy_api_key_should_still_work_and_disclose_api_key
    legacy = @user.api_key
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => legacy}
    assert_response :ok
    assert_equal legacy, response.parsed_body['user']['api_key']
  end

  def test_users_current_should_not_disclose_api_key_to_token
    @user.api_key
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => @plaintext}
    assert_response :ok
    assert_not response.parsed_body['user'].has_key?('api_key')
  end

  def test_my_account_should_not_disclose_api_key_to_token
    @user.api_key
    get '/my/account.json', :headers => {'X-Redmine-API-Key' => @plaintext}
    assert_response :ok
    assert_not response.parsed_body['user'].has_key?('api_key')
  end

  def test_admin_token_should_not_disclose_other_users_api_key
    admin_token = PersonalAccessToken.create!(:user => User.find(1), :name => 'admin', :expiration_date => User.find(1).today + 5)
    get '/users/2.json', :headers => {'X-Redmine-API-Key' => admin_token.plaintext_token}
    assert_response :ok
    assert_not response.parsed_body['user'].has_key?('api_key')
  end

  def test_admin_token_should_accept_switch_user_header_without_disclosing_api_key
    admin_token = PersonalAccessToken.create!(:user => User.find(1), :name => 'admin', :expiration_date => User.find(1).today + 5)
    get '/users/current.json',
        :headers => {'X-Redmine-API-Key' => admin_token.plaintext_token, 'X-Redmine-Switch-User' => 'jsmith'}
    assert_response :ok
    assert_equal 'jsmith', response.parsed_body['user']['login']
    assert_not response.parsed_body['user'].has_key?('api_key')
  end

  def test_should_deny_token_of_user_who_must_change_password
    @user.update_column(:must_change_passwd, true)
    get '/users/current.json', :headers => credentials(@plaintext, 'X')
    assert_response :forbidden
  end

  def test_basic_auth_with_pat_username_should_not_call_try_to_login
    User.expects(:try_to_login).never
    get '/users/current.json', :headers => credentials(@plaintext, 'X')
    assert_response :ok
  end

  def test_basic_auth_with_pat_username_should_not_leak_plaintext_into_logs
    io = StringIO.new
    logger = ActiveSupport::Logger.new(io)
    logger.level = Logger::DEBUG
    previous_level = Rails.logger.level
    Rails.logger.level = Logger::DEBUG
    Rails.logger.broadcast_to(logger)
    begin
      get '/users/current.json', :headers => credentials(@plaintext, 'X')
    ensure
      Rails.logger.stop_broadcasting_to(logger)
      Rails.logger.level = previous_level
    end
    assert_response :ok
    assert_not_include @plaintext, io.string
  end

  def test_basic_auth_with_pat_username_should_authenticate_owner_with_active_twofa
    @user.update!(:twofa_scheme => 'totp')
    assert @user.reload.twofa_active?
    get '/users/current.json', :headers => credentials(@plaintext, 'X')
    assert_response :ok
    assert_equal 'jsmith', response.parsed_body['user']['login']
  end

  def test_admin_token_should_deny_switch_user_header_to_locked_user
    admin_token = PersonalAccessToken.create!(:user => User.find(1), :name => 'admin', :expiration_date => User.find(1).today + 5)
    get '/users/current.json',
        :headers => {'X-Redmine-API-Key' => admin_token.plaintext_token, 'X-Redmine-Switch-User' => 'dlopper2'}
    assert_response :precondition_failed
  end

  # A personal access token is accepted anywhere the REST API accepts a
  # legacy API key, including formats such as atom and csv that are not
  # limited to the xml/json API request path. This mirrors the legacy
  # key's own behaviour and is intentional.
  def test_atom_feed_should_authenticate_with_token_like_legacy_key
    get "/issues.atom?key=#{@user.api_key}"
    assert_response :success
    assert_include 'Issue on project 2', response.body

    get "/issues.atom?key=#{@plaintext}"
    assert_response :success
    assert_include 'Issue on project 2', response.body
  end

  def test_csv_export_should_authenticate_with_token_like_legacy_key
    get "/issues.csv?key=#{@user.api_key}"
    assert_response :success
    assert_include 'Issue on project 2', response.body

    get "/issues.csv?key=#{@plaintext}"
    assert_response :success
    assert_include 'Issue on project 2', response.body
  end

  def test_expired_token_on_atom_feed_should_not_show_private_content
    travel_to @token.expires_on + 1.second do
      get "/issues.atom?key=#{@plaintext}"
    end
    assert_response :success
    assert_not_include 'Issue on project 2', response.body
  end

  def test_token_should_be_filtered_from_logs
    io = StringIO.new
    logger = ActiveSupport::Logger.new(io)
    Rails.logger.broadcast_to(logger)
    begin
      get "/issues.json?key=#{@plaintext}"
    ensure
      Rails.logger.stop_broadcasting_to(logger)
    end
    assert_response :ok
    lines = io.string.lines
    started_line = lines.find {|line| line.include?('Started GET')}
    parameters_line = lines.find {|line| line.include?('Parameters:')}
    assert started_line, 'expected a "Started GET" line in the log'
    assert parameters_line, 'expected a "Parameters:" line in the log'
    assert_include '[FILTERED]', started_line
    assert_include '[FILTERED]', parameters_line
    assert_not_include @plaintext, io.string
  end

  def test_tokens_should_not_be_manageable_through_the_api
    assert_no_difference 'PersonalAccessToken.count' do
      post '/my/personal_access_tokens.json',
           :params => {:personal_access_token => {:name => 'x', :expiration_date => (@user.today + 5).iso8601}},
           :headers => {'X-Redmine-API-Key' => @plaintext}
    end
    assert_response :not_found

    assert_no_difference 'PersonalAccessToken.count' do
      post '/my/personal_access_tokens.json',
           :params => {:personal_access_token => {:name => 'x', :expiration_date => (@user.today + 5).iso8601}},
           :headers => {'X-Redmine-API-Key' => @user.api_key}
    end
    assert_response :not_found
  end
end
