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
  # Structured audit log of REST API requests
  module ApiAudit
    DEFAULT_RETENTION_DAYS = 90

    # Retention period in days, a non-positive setting falls back to the default
    def self.retention_days
      days = Setting.api_audit_log_retention_days.to_i
      days > 0 ? days : DEFAULT_RETENTION_DAYS
    end

    # Deletes audit records older than the retention period and returns the
    # number of deleted events
    def self.prune(now=Time.now)
      ApiAuditEvent.prune(now - retention_days.days)
    end
  end
end
