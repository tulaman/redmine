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

# An anomaly notification sent by the API audit scanner, kept to avoid
# sending the same alert again
class ApiAuditAlert < ApplicationRecord
  KINDS = %w(failures volume new_ip).freeze

  validates_inclusion_of :kind, :in => KINDS
  validates_presence_of :subject

  # Returns the set of subjects of the alerts of kind sent at or after time
  def self.subjects_sent_since(kind, time)
    where(:kind => kind).where("#{table_name}.created_on >= ?", time).distinct.pluck(:subject).to_set
  end

  # Deletes alerts created before the given time, in batches of id ranges
  # like ApiAuditEvent.prune, and returns the number of deleted alerts
  def self.prune(before)
    where("#{table_name}.created_on < ?", before).
      in_batches(:of => ApiAuditEvent::PRUNE_BATCH_SIZE, :use_ranges => true).delete_all
  end
end
