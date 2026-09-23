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

class Redmine::ApiTest::ApiAuditLogTest < Redmine::ApiTest::Base
  def teardown
    User.current = nil
    super
  end

  def with_audit(&)
    with_settings(:api_audit_log_enabled => '1', &)
  end

  def test_should_not_record_when_disabled
    assert_no_difference 'ApiAuditEvent.count' do
      get '/projects.json'
    end
  end

  def test_should_record_anonymous_request
    with_audit do
      assert_difference 'ApiAuditEvent.count', 1 do
        get '/projects.json'
      end
    end
    event = ApiAuditEvent.last
    assert_equal ['none', false, nil, 'GET', '/projects.json', 200, '127.0.0.1'],
                 [event.auth_kind, event.auth_failed, event.user_id, event.http_method, event.path, event.status, event.ip]
  end

  # Performs a request whose Client-Ip and X-Forwarded-For headers disagree,
  # which makes request.remote_ip raise. Rails::Rack::Logger also calls
  # remote_ip when logging at info level, so the log level is raised to
  # warn to check the application alone.
  def get_with_spoofed_ip(path, forwarded_for='2.2.2.2')
    level = Rails.logger.level
    Rails.logger.level = :warn
    get path, :headers => {'Client-Ip' => '1.1.1.1', 'X-Forwarded-For' => forwarded_for}
  ensure
    Rails.logger.level = level
  end

  def test_spoofed_ip_headers_should_not_break_request_when_disabled
    get_with_spoofed_ip '/projects.json'
    assert_response :success
  end

  def test_spoofed_ip_headers_should_not_break_request_when_enabled
    with_audit do
      assert_difference 'ApiAuditEvent.count', 1 do
        get_with_spoofed_ip '/projects.json'
      end
    end
    assert_response :success
    assert_not_nil ApiAuditEvent.last.ip
  end

  def test_spoofed_ip_headers_should_record_peer_address
    with_audit do
      get_with_spoofed_ip '/projects.json', '2.2.2.2, =1+1'
    end
    assert_response :success
    assert_equal '127.0.0.1', ApiAuditEvent.last.ip
  end

  def test_failure_to_collect_audit_data_should_not_break_request
    Redmine::ApiAudit::Credential.any_instance.stubs(:to_h).raises(RuntimeError, 'boom')
    with_audit do
      assert_no_difference 'ApiAuditEvent.count' do
        get '/projects.json'
      end
    end
    assert_response :success
  end

  def test_should_record_rejected_credential
    with_audit do
      get '/users/current.json', :headers => {'X-Redmine-API-Key' => 'x' * 40}
    end
    assert_response :unauthorized
    event = ApiAuditEvent.last
    assert_equal ['api_key', true, 401], [event.auth_kind, event.auth_failed, event.status]
  end

  def test_should_record_final_status_of_not_found
    with_audit do
      get '/issues/999999.json'
    end
    assert_equal 404, ApiAuditEvent.last.status
  end

  def test_should_record_status_rendered_by_rescue_from
    IssuesController.any_instance.stubs(:index).raises(::Unauthorized)
    with_audit do
      get '/issues.json'
    end
    assert_response :unauthorized
    assert_equal 401, ApiAuditEvent.last.status
  end

  def test_should_record_server_error
    IssuesController.any_instance.stubs(:index).raises(RuntimeError, 'boom')
    with_audit do
      get '/issues.json'
    end
    assert_response :internal_server_error
    assert_equal 500, ApiAuditEvent.last.status
  end

  def test_should_record_http_method
    with_audit do
      post '/projects.json', :params => {:project => {:name => 'Audit'}}
    end
    assert_equal 'POST', ApiAuditEvent.last.http_method
  end

  def test_should_not_record_html_request
    with_audit do
      assert_no_difference 'ApiAuditEvent.count' do
        get '/projects'
      end
    end
  end

  def test_should_never_store_personal_access_token_value
    user = User.find(2)
    token = PersonalAccessToken.create!(:user => user, :name => 'Audit', :expiration_date => user.today + 30)
    with_audit do
      get "/users/current.json?key=#{token.plaintext_token}"
    end
    assert_response :ok
    event = ApiAuditEvent.last
    assert_equal token.id, event.personal_access_token_id
    event.attributes.each_value do |value|
      assert_not_include token.plaintext_token, value.to_s
    end
  end

  def test_write_failure_should_not_break_response
    ApiAuditEvent.stubs(:create!).raises(ActiveRecord::StatementInvalid, 'database is locked')
    Rails.logger.stubs(:error)
    Rails.logger.expects(:error).with do |message|
      message.include?('API audit event could not be recorded: ActiveRecord::StatementInvalid') &&
        !message.include?('/projects.json') && !message.include?('127.0.0.1')
    end
    with_audit do
      get '/projects.json'
    end
    assert_response :ok
  end
end
