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

class ApiAuditEventTest < ActiveSupport::TestCase
  def valid_attributes
    {:auth_kind => 'pat', :user_id => 2, :http_method => 'GET',
     :path => '/issues.json', :status => 200, :ip => '10.0.0.1'}
  end

  def test_create_should_set_created_on
    event = ApiAuditEvent.create!(valid_attributes)
    assert_not_nil event.created_on
    assert_equal false, event.auth_failed
  end

  def test_should_require_known_auth_kind
    event = ApiAuditEvent.new(valid_attributes.merge(:auth_kind => 'password'))
    assert_not event.valid?
    assert_include :auth_kind, event.errors.attribute_names
  end

  def test_should_require_request_attributes
    event = ApiAuditEvent.new(:auth_kind => 'none')
    assert_not event.valid?
    assert_include :http_method, event.errors.attribute_names
    assert_include :path, event.errors.attribute_names
    assert_include :status, event.errors.attribute_names
  end

  def test_should_truncate_long_path
    event = ApiAuditEvent.create!(valid_attributes.merge(:path => '/' + ('a' * 299)))
    assert_equal 255, event.reload.path.length
  end

  def test_should_accept_ipv6_address
    ip = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    event = ApiAuditEvent.create!(valid_attributes.merge(:ip => ip))
    assert_equal ip, event.reload.ip
  end

  def test_should_scrub_invalid_utf8_from_path
    path = +"/issues/\xFF.json"
    path.force_encoding('UTF-8')
    event = ApiAuditEvent.create!(valid_attributes.merge(:path => path))
    assert event.reload.path.valid_encoding?
  end

  def test_should_require_http_method_within_limit
    event = ApiAuditEvent.new(valid_attributes.merge(:http_method => 'A' * 11))
    assert_not event.valid?
    assert_include :http_method, event.errors.attribute_names
  end
end
