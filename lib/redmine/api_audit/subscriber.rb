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
    # Stores one ApiAuditEvent per API request from the
    # process_action.action_controller notification
    module Subscriber
      def self.call(event)
        attributes = event.payload[:redmine_api_audit]
        return unless attributes && Setting.api_audit_log_enabled?

        ApiAuditEvent.create!(attributes.merge(:status => event.payload[:status] || 500))
      rescue StandardError => e
        # Auditing must never break or alter the API response
        Rails.logger.error "API audit event could not be recorded: #{e.class}: #{e.message}"
      end
    end
  end
end
