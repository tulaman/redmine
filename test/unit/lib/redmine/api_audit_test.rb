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

require_relative '../../../test_helper'

class Redmine::ApiAuditTest < ActiveSupport::TestCase
  def create_event(created_on)
    ApiAuditEvent.create!(:auth_kind => 'none', :http_method => 'GET', :path => '/projects.json',
                          :status => 200, :created_on => created_on)
  end

  def test_retention_days_should_default_to_90
    assert_equal 90, Redmine::ApiAudit.retention_days
  end

  def test_retention_days_should_use_setting
    with_settings :api_audit_log_retention_days => '30' do
      assert_equal 30, Redmine::ApiAudit.retention_days
    end
  end

  def test_retention_days_should_fall_back_to_default_when_not_positive
    ['0', '-5'].each do |value|
      with_settings :api_audit_log_retention_days => value do
        assert_equal 90, Redmine::ApiAudit.retention_days
      end
    end
  end

  def test_prune_should_delete_events_older_than_retention
    now = Time.now
    old = create_event(now - 31.days)
    recent = create_event(now - 29.days)
    with_settings :api_audit_log_retention_days => '30' do
      assert_equal 1, Redmine::ApiAudit.prune(now)
    end
    assert_not ApiAuditEvent.exists?(old.id)
    assert ApiAuditEvent.exists?(recent.id)
  end
end
