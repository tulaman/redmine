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

# One REST API request recorded by the API audit log. Only identifiers are
# stored: never a key, token, password, header, query string or body.
class ApiAuditEvent < ApplicationRecord
  AUTH_KINDS = %w(none api_key pat oauth basic).freeze
  PATH_LENGTH_LIMIT = 255

  belongs_to :user, :optional => true
  belongs_to :switched_from_user, :class_name => 'User', :optional => true
  belongs_to :personal_access_token, :optional => true
  belongs_to :oauth_application, :class_name => 'Doorkeeper::Application', :optional => true

  before_validation :truncate_path

  validates_inclusion_of :auth_kind, :in => AUTH_KINDS
  validates_presence_of :http_method, :path, :status
  validates_length_of :http_method, :maximum => 10

  private

  def truncate_path
    self.path = path.dup.force_encoding(Encoding::UTF_8).scrub[0, PATH_LENGTH_LIMIT] if path
  end
end
