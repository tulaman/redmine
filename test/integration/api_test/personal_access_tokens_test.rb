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

  # A leaked PAT must not be usable to redirect the "forgot password" email to
  # an address the attacker controls, which would otherwise escalate a stolen
  # PAT into a full web session.
  def test_account_update_with_token_should_reject_mail_change
    put '/my/account.json',
        :params => {:user => {:mail => 'jsmith-new@somenet.foo'}},
        :headers => {'X-Redmine-API-Key' => @plaintext}
    assert_response :unprocessable_content
    assert_equal 'jsmith@somenet.foo', @user.reload.mail
  end

  def test_account_update_html_with_token_should_reject_mail_change
    put '/my/account',
        :params => {:user => {:mail => 'jsmith-new@somenet.foo'}},
        :headers => {'X-Redmine-API-Key' => @plaintext}
    assert_response :unprocessable_content
    assert_select_error /cannot be changed/
    assert_equal 'jsmith@somenet.foo', @user.reload.mail
  end

  def test_account_update_with_token_should_allow_other_attributes
    put '/my/account.json',
        :params => {:user => {:firstname => 'Changed'}},
        :headers => {'X-Redmine-API-Key' => @plaintext}
    assert_response :no_content
    assert_equal 'Changed', @user.reload.firstname
  end

  # The switch-user header propagates the admin's PAT onto the impersonated
  # user (see ApplicationController#find_current_user), so the mail-change
  # block must still apply to the switched-to user and not be bypassable by
  # impersonation.
  def test_account_update_with_switched_user_token_should_reject_mail_change
    admin_token = PersonalAccessToken.create!(:user => User.find(1), :name => 'admin', :expiration_date => User.find(1).today + 5)
    put '/my/account.json',
        :params => {:user => {:mail => 'jsmith-new@somenet.foo'}},
        :headers => {'X-Redmine-API-Key' => admin_token.plaintext_token, 'X-Redmine-Switch-User' => 'jsmith'}
    assert_response :unprocessable_content
    assert_equal 'jsmith@somenet.foo', @user.reload.mail
  end

  # Closes the "add a secondary address, then reset the password to it"
  # variant of the mail-change escalation: EmailAddressesController must not
  # be reachable with a PAT either.
  def test_email_addresses_controller_should_not_be_reachable_with_token
    assert_no_difference 'EmailAddress.count' do
      post "/users/#{@user.id}/email_addresses.json",
           :params => {:email_address => {:address => 'attacker@example.com'}},
           :headers => {'X-Redmine-API-Key' => @plaintext}
    end
    assert_not_equal 2, response.status / 100
  end

  def test_account_update_with_legacy_key_should_still_allow_mail_change
    legacy = @user.api_key
    put '/my/account.json',
        :params => {:user => {:mail => 'jsmith-new@somenet.foo'}},
        :headers => {'X-Redmine-API-Key' => legacy}
    assert_response :no_content
    assert_equal 'jsmith-new@somenet.foo', @user.reload.mail
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

  # Deliberate parity with the legacy key: a token passed as ?key= on an HTML
  # page ends up in that page's own links, in browser history and in the
  # Referer header, so the header transport is the recommended one. This
  # behaviour stays as it is; the test only pins it, not endorses it.
  def test_issues_html_should_authenticate_with_token_like_legacy_key
    get "/issues?key=#{@user.api_key}"
    assert_response :success
    assert_include 'Issue on project 2', response.body

    get "/issues?key=#{@plaintext}"
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

  # ApplicationController#require_login builds the login redirect's back_url
  # from the full request url. A PAT-shaped key in that url must not survive
  # into the redirect, the follow-up login request's logs, or the login
  # form, even though the action never consults the key for authentication.
  def test_login_redirect_should_strip_pat_shaped_key_from_back_url
    io = StringIO.new
    logger = ActiveSupport::Logger.new(io)
    Rails.logger.broadcast_to(logger)
    begin
      get "/my/personal_access_tokens?foo=bar&key=#{@plaintext}"
      assert_response :redirect
      assert_not_include @plaintext, response.location
      back_url = Rack::Utils.parse_query(URI.parse(response.location).query)['back_url']
      assert_include 'foo=bar', back_url
      assert_not_include 'key=', back_url
      follow_redirect!
    ensure
      Rails.logger.stop_broadcasting_to(logger)
    end
    assert_response :success
    assert_not_include @plaintext, response.body
    assert_not_include @plaintext, io.string
  end

  def test_login_redirect_should_strip_expired_pat_shaped_key_from_back_url
    io = StringIO.new
    logger = ActiveSupport::Logger.new(io)
    Rails.logger.broadcast_to(logger)
    begin
      travel_to @token.expires_on + 1.second do
        get "/my/account?key=#{@plaintext}"
        assert_response :redirect
        assert_not_include @plaintext, response.location
        follow_redirect!
      end
    ensure
      Rails.logger.stop_broadcasting_to(logger)
    end
    assert_response :success
    assert_not_include @plaintext, response.body
    assert_not_include @plaintext, io.string
  end

  def test_login_redirect_should_keep_legacy_key_in_back_url
    legacy = @user.api_key
    get "/my/personal_access_tokens?key=#{legacy}"
    assert_response :redirect
    back_url = Rack::Utils.parse_query(URI.parse(response.location).query)['back_url']
    assert_include "key=#{legacy}", back_url
  end

  # The stripping guard must agree with whatever the auth layer itself
  # authenticated with, on every quirk of query string parsing, otherwise a
  # variant that still authenticates could still leak.
  def test_login_redirect_should_strip_pat_shaped_key_with_duplicate_param
    # Rack/Rails keep the *last* occurrence of a repeated param for both
    # params[:key] and auth; a naive first-match strip would miss it.
    get "/my/personal_access_tokens?key=not-a-token&key=#{@plaintext}"
    assert_response :redirect
    assert_not_include @plaintext, response.location
  end

  def test_login_redirect_should_strip_pat_shaped_key_with_escaped_param_name
    # '%6Bey' is 'key' with its first letter percent-escaped; Rack/Rails
    # decode the param name before matching it, so this still authenticates.
    get "/my/personal_access_tokens?%6Bey=#{@plaintext}"
    assert_response :redirect
    assert_not_include @plaintext, response.location
  end

  def test_login_redirect_should_strip_pat_shaped_key_with_non_ascii_query
    # A raw (unescaped) non-ASCII byte sequence in the query string, as a
    # client talking raw HTTP rather than going through URI escaping could
    # send, must not make the stripping raise (e.g. URI.parse chokes on it)
    # and fall back to leaking the whole, unmodified url. rack-test itself
    # refuses to build a request from such a raw url (it URI-parses the
    # path before sending), so this exercises the controller method
    # directly with a url string carrying the same raw bytes.
    get '/my/personal_access_tokens', :params => {:key => @plaintext}
    controller = @controller
    raw_url = "http://test.host/my/personal_access_tokens?q=Ünicode&key=#{@plaintext}"
    result = controller.send(:strip_personal_access_token_from_url, raw_url)
    assert_not_include @plaintext, result
  end

  # An expired token, an unknown token and a token whose owner got locked
  # after the token was issued must all be rejected the same way, so that
  # the response gives an attacker no signal about which of these applies.
  def test_expired_unknown_and_locked_owner_tokens_should_give_identical_401_responses
    responses = {}

    travel_to @token.expires_on + 1.second do
      get '/users/current.json', :headers => {'X-Redmine-API-Key' => @plaintext}
      responses[:expired] = [response.status, response.body, response.headers['WWW-Authenticate']]
    end

    get '/users/current.json', :headers => {'X-Redmine-API-Key' => 'redmine_pat_' + ('x' * 40)}
    responses[:unknown] = [response.status, response.body, response.headers['WWW-Authenticate']]

    # Locked last: locking the owner is a persistent state change, so it
    # must not influence the other two requests above.
    @user.lock!
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => @plaintext}
    responses[:locked] = [response.status, response.body, response.headers['WWW-Authenticate']]

    assert_equal 401, responses[:expired][0]
    assert_equal responses[:expired], responses[:unknown]
    assert_equal responses[:expired], responses[:locked]
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
