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

module ApiAuditEventQueriesHelper
  RECORD_COLUMNS = [:user, :switched_from_user, :personal_access_token, :oauth_application].freeze

  def column_value(column, object, value)
    return super unless object.is_a?(ApiAuditEvent)

    case column.name
    when :auth_kind
      api_audit_auth_kind_label(value)
    when :user, :switched_from_user
      value ? super : api_audit_deleted_record(object, column)
    when :personal_access_token, :oauth_application
      value ? api_audit_record_name(value) : api_audit_deleted_record(object, column)
    else
      super
    end
  end

  def csv_value(column, object, value)
    return super unless object.is_a?(ApiAuditEvent)

    if column.name == :auth_kind
      api_audit_auth_kind_label(value)
    elsif RECORD_COLUMNS.include?(column.name)
      value ? api_audit_record_name(value) : api_audit_deleted_record(object, column)
    else
      super
    end
  end

  def api_audit_auth_kind_label(kind)
    l("label_api_audit_auth_kind_#{kind}")
  end

  def api_audit_record_name(record)
    case record
    when PersonalAccessToken
      "#{record.name} (#{record.masked_value})"
    when Principal
      record.to_s
    else
      record.name
    end
  end

  # Returns a label for a referenced record that no longer exists, or an
  # empty string when the event never referenced one
  def api_audit_deleted_record(object, column)
    id = object.public_send(:"#{column.name}_id")
    id ? l(:label_api_audit_deleted_record, :id => id) : ''
  end
end
