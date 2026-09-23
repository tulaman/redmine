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

require_relative '../test_helper'

class AdminApiAuditEventsControllerTest < Redmine::ControllerTest
  def setup
    @request.session[:user_id] = 1
  end

  def create_event(attributes={})
    ApiAuditEvent.create!({:auth_kind => 'api_key', :user_id => 2, :http_method => 'GET',
                           :path => '/issues.json', :status => 200, :ip => '10.0.0.1'}.merge(attributes))
  end

  def test_index
    create_event(:path => '/projects/ecookbook.json')
    get :index
    assert_response :success
    assert_select 'table.list.api-audit-events tbody tr', 1
    assert_select 'td.path', :text => '/projects/ecookbook.json'
  end

  def test_index_should_escape_client_controlled_values
    create_event(:path => '/x<script>alert(1)</script>', :ip => '<b>10.0.0.1</b>')
    get :index, :params => {:set_filter => '1', :c => %w(created_on path ip)}
    assert_response :success
    assert_select 'td.path', :text => '/x<script>alert(1)</script>'
    assert_select 'td.ip', :text => '<b>10.0.0.1</b>'
    assert_select 'td.path script', 0
    assert_select 'td.ip b', 0
  end

  def test_index_should_require_admin
    @request.session[:user_id] = 2
    get :index
    assert_response :forbidden
  end

  def test_index_should_require_login
    @request.session[:user_id] = nil
    get :index
    assert_response :redirect
    assert_match %r{/login}, response.location
  end

  def test_index_should_warn_when_auditing_is_disabled
    with_settings :api_audit_log_enabled => '0' do
      get :index
    end
    assert_select 'div.flash.warning'
  end

  def test_index_should_not_warn_when_auditing_is_enabled
    with_settings :api_audit_log_enabled => '1' do
      get :index
    end
    assert_select 'div.flash.warning', 0
  end

  def test_index_with_ip_filter
    create_event(:ip => '10.0.0.9', :path => '/matching.json')
    create_event(:ip => '10.0.0.1', :path => '/other.json')
    get :index, :params => {:set_filter => '1', :f => ['ip'], :op => {'ip' => '='}, :v => {'ip' => ['10.0.0.9']}}
    assert_response :success
    assert_select 'td.path', :text => '/matching.json'
    assert_select 'td.path', :text => '/other.json', :count => 0
  end

  def test_index_should_show_personal_access_token_and_deleted_one
    user = User.find(2)
    token = PersonalAccessToken.create!(:user => user, :name => 'CI', :expiration_date => user.today + 30)
    create_event(:auth_kind => 'pat', :personal_access_token_id => token.id)
    create_event(:auth_kind => 'pat', :personal_access_token_id => 999_999)
    get :index, :params => {:set_filter => '1', :f => ['created_on'], :op => {'created_on' => '>t-'},
                            :v => {'created_on' => ['7']},
                            :c => %w(created_on personal_access_token)}
    assert_response :success
    assert_select 'td.personal_access_token', :text => "CI (#{token.masked_value})"
    assert_select 'td.personal_access_token', :text => 'deleted (#999999)'
  end

  def test_index_csv
    create_event(:path => '/projects.json')
    get :index, :params => {:format => 'csv'}
    assert_response :success
    assert_equal 'text/csv; header=present', @response.media_type
    lines = response.body.chomp.split("\n")
    assert_equal 2, lines.size
    assert_include '/projects.json', lines.last
  end

  def test_index_csv_should_be_capped
    3.times {|i| create_event(:path => "/p#{i}.json")}
    stub_const(AdminApiAuditEventsController, :CSV_EXPORT_LIMIT, 2) do
      get :index, :params => {:format => 'csv'}
    end
    assert_response :success
    assert_equal 3, response.body.chomp.split("\n").size
  end
end
