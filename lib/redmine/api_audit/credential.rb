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

module Redmine
  module ApiAudit
    # Describes the credential presented with an API request and whether it
    # authenticated. It only holds identifiers, never a secret, and its
    # attributes match the ApiAuditEvent columns.
    Credential = Data.define(:auth_kind, :auth_failed, :user_id, :switched_from_user_id,
                             :personal_access_token_id, :oauth_application_id) do
      def initialize(auth_kind:, auth_failed: false, user_id: nil, switched_from_user_id: nil,
                     personal_access_token_id: nil, oauth_application_id: nil)
        super
      end
    end
  end
end
