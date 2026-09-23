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

class ApiAuditEventQuery < Query
  HTTP_METHODS = %w(GET HEAD POST PUT PATCH DELETE).freeze

  self.layout = 'admin'
  self.queried_class = ApiAuditEvent

  self.available_columns = [
    QueryColumn.new(:created_on, :sortable => "#{ApiAuditEvent.table_name}.created_on", :default_order => 'desc'),
    QueryColumn.new(:user),
    QueryColumn.new(:switched_from_user),
    QueryColumn.new(:auth_kind, :sortable => "#{ApiAuditEvent.table_name}.auth_kind"),
    QueryColumn.new(:auth_failed, :sortable => "#{ApiAuditEvent.table_name}.auth_failed"),
    QueryColumn.new(:personal_access_token, :caption => :label_personal_access_token),
    QueryColumn.new(:oauth_application),
    QueryColumn.new(:http_method, :sortable => "#{ApiAuditEvent.table_name}.http_method"),
    QueryColumn.new(:path, :sortable => "#{ApiAuditEvent.table_name}.path"),
    QueryColumn.new(:status, :sortable => "#{ApiAuditEvent.table_name}.status"),
    QueryColumn.new(:ip, :sortable => "#{ApiAuditEvent.table_name}.ip", :caption => :field_remote_ip)
  ]

  def self.visible(*args)
    user = args.shift || User.current
    if user.admin?
      where('1=1')
    else
      where('1=0')
    end
  end

  def initialize(attributes=nil, *args)
    super(attributes)
    self.filters ||= {'created_on' => {:operator => '>t-', :values => ['7']}}
  end

  def initialize_available_filters
    add_available_filter 'created_on', :type => :date_past
    add_available_filter 'user_id', :type => :list_optional, :values => lambda {users_values}, :label => :field_user
    add_available_filter 'auth_kind', :type => :list, :values => lambda {auth_kind_values}
    add_available_filter 'auth_failed', :type => :list,
                         :values => [[l(:general_text_yes), '1'], [l(:general_text_no), '0']]
    add_available_filter 'personal_access_token_id', :type => :integer, :label => :label_personal_access_token
    add_available_filter 'status', :type => :integer
    add_available_filter 'http_method', :type => :list, :values => HTTP_METHODS.map {|m| [m, m]}
    add_available_filter 'ip', :type => :string, :label => :field_remote_ip
    add_available_filter 'path', :type => :string
  end

  def visible?(user=User.current)
    user&.admin?
  end

  def editable_by?(user)
    user&.admin?
  end

  def users_values
    # QueriesController#new renders filter values for any logged-in user, so
    # never list every account (including locked ones) to non-admins
    return [] unless User.current.admin?

    User.logged.sorted.map {|user| [user.name, user.id.to_s]}
  end

  def auth_kind_values
    ApiAuditEvent::AUTH_KINDS.map {|kind| [l("label_api_audit_auth_kind_#{kind}"), kind]}
  end

  def default_columns_names
    @default_columns_names ||= [:created_on, :user, :auth_kind, :auth_failed, :http_method, :path, :status, :ip]
  end

  def default_sort_criteria
    [['created_on', 'desc']]
  end

  def base_scope
    ApiAuditEvent.where(statement)
  end

  def results_scope(options={})
    order_option = [group_by_sort_order, (options[:order] || sort_clause)].flatten.reject(&:blank?)

    base_scope.
      preload(:user, :switched_from_user, :personal_access_token, :oauth_application).
      order(order_option).
      order("#{ApiAuditEvent.table_name}.id DESC")
  end

  def sql_for_auth_failed_field(field, operator, value)
    value = value.first
    return if value.nil?

    true_value = operator == '=' ? '1' : '0'
    connection = self.class.connection
    sql_value = value.to_s == true_value ? connection.quoted_true : connection.quoted_false
    "(#{ApiAuditEvent.table_name}.auth_failed = #{sql_value})"
  end
end
