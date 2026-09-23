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

class ApiAuditEventQueryTest < ActiveSupport::TestCase
  def setup
    User.current = User.find(1)
  end

  def teardown
    User.current = nil
  end

  def create_event(attributes={})
    ApiAuditEvent.create!({:auth_kind => 'api_key', :user_id => 2, :http_method => 'GET',
                           :path => '/issues.json', :status => 200, :ip => '10.0.0.1'}.merge(attributes))
  end

  def query_with(filters)
    query = ApiAuditEventQuery.new(:name => '_')
    query.filters = filters
    query
  end

  def test_should_be_visible_to_admins_only
    query = ApiAuditEventQuery.new(:name => '_')
    assert query.visible?(User.find(1))
    assert_not query.visible?(User.find(2))
  end

  def test_default_filter_should_limit_to_last_seven_days
    recent = create_event(:created_on => 1.day.ago)
    old = create_event(:created_on => 8.days.ago)
    results = ApiAuditEventQuery.new(:name => '_').results_scope.to_a
    assert_include recent, results
    assert_not_include old, results
  end

  def test_results_should_be_sorted_newest_first_by_default
    older = create_event(:created_on => 2.hours.ago)
    newer = create_event(:created_on => 1.hour.ago)
    assert_equal [newer, older], ApiAuditEventQuery.new(:name => '_').results_scope.to_a
  end

  def test_filter_by_ip
    matching = create_event(:ip => '10.0.0.9')
    other = create_event(:ip => '10.0.0.1')
    results = query_with('ip' => {:operator => '=', :values => ['10.0.0.9']}).results_scope.to_a
    assert_equal [matching], results
    assert_not_include other, results
  end

  def test_filter_by_auth_failed
    failed = create_event(:auth_failed => true, :user_id => nil)
    create_event
    results = query_with('auth_failed' => {:operator => '=', :values => ['1']}).results_scope.to_a
    assert_equal [failed], results
  end

  def test_filter_by_status_greater_or_equal
    denied = create_event(:status => 403)
    create_event(:status => 200)
    results = query_with('status' => {:operator => '>=', :values => ['400']}).results_scope.to_a
    assert_equal [denied], results
  end

  def test_filter_by_user
    mine = create_event(:user_id => 3)
    create_event(:user_id => 2)
    results = query_with('user_id' => {:operator => '=', :values => ['3']}).results_scope.to_a
    assert_equal [mine], results
  end

  def test_users_values_should_be_empty_for_non_admin
    query = ApiAuditEventQuery.new(:name => '_')
    assert_not_empty query.users_values
    User.current = User.find(2)
    assert_empty query.users_values
  end

  def test_available_filters
    names = ApiAuditEventQuery.new(:name => '_').available_filters.keys
    assert_equal %w(created_on user_id auth_kind auth_failed personal_access_token_id status http_method ip path).sort,
                 names.sort
  end
end
