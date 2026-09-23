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
    # Looks for anomalous API activity in the audit log and sends
    # notifications. It only reads recorded events: it never blocks, delays
    # or alters a request. Runs are idempotent, alerts already sent are
    # recorded in ApiAuditAlert and not sent again.
    #
    # Failures and volume findings are sent to administrators as one digest
    # per run, so that an attacker rotating IP addresses cannot trigger one
    # mail per address.
    class Scanner
      FAILURES_WINDOW = 10.minutes
      VOLUME_WINDOW = 60.minutes
      NEW_IP_LOOKBACK = 24.hours
      REPEAT_INTERVAL = 1.hour
      # Maximum number of findings listed in the administrators' digest
      DIGEST_LIMIT = 20
      STEPS = [:detect_failures, :detect_volume, :send_digest, :detect_new_ips].freeze

      def initialize(now: Time.now)
        @now = now
      end

      # Runs all detectors and sends the notifications. Returns false if any
      # detector or mail delivery failed.
      def run
        return true unless Setting.api_audit_log_enabled?

        @findings = []
        @delivery_failed = false
        succeeded = STEPS.map do |step|
          send(step)
          true
        rescue StandardError => e
          Rails.logger.error "API audit #{step} failed: #{e.class}: #{e.message}"
          false
        end.all?
        succeeded && !@delivery_failed
      end

      private

      # Repeated authentication failures from one IP address
      def detect_failures
        threshold = Setting.api_audit_alert_failures_threshold.to_i
        return if threshold <= 0

        counts = ApiAuditEvent.failed.since(@now - FAILURES_WINDOW).where.not(:ip => nil).
                   group(:ip).having('COUNT(*) >= ?', threshold).count
        collect_findings('failures', counts, FAILURES_WINDOW)
      end

      # Excessive request volume of one user
      def detect_volume
        threshold = Setting.api_audit_alert_volume_threshold.to_i
        return if threshold <= 0

        counts = ApiAuditEvent.succeeded.since(@now - VOLUME_WINDOW).where.not(:user_id => nil).
                   group(:user_id).having('COUNT(*) >= ?', threshold).count
        collect_findings('volume', counts, VOLUME_WINDOW)
      end

      # Adds the counts that were not already reported within the repeat
      # interval to the findings of the digest. Findings are plain hashes of
      # strings and integers so that the mail can be delivered later.
      def collect_findings(kind, counts, window)
        return if counts.empty?

        reported = ApiAuditAlert.subjects_sent_since(kind, @now - REPEAT_INTERVAL)
        counts.each do |subject, count|
          subject = subject.to_s
          next if reported.include?(subject)

          @findings << {'kind' => kind, 'subject' => subject, 'count' => count, 'minutes' => (window / 60).to_i}
        end
      end

      # Sends one digest of the findings to each active administrator, then
      # records every finding, including the ones not listed in the digest.
      # Nothing is recorded if every delivery failed, so that the findings
      # are sent again on the next run.
      def send_digest
        return if @findings.empty?

        findings = @findings.sort_by {|f| [-f['count'], f['kind'], f['subject']]}
        listed = findings.first(DIGEST_LIMIT)
        omitted = findings.size - listed.size
        admins = User.active.where(:admin => true).to_a
        delivered = admins.map {|admin| deliver {Mailer.deliver_api_audit_digest(admin, listed, omitted)}}
        return if admins.any? && delivered.none?

        ApiAuditAlert.transaction do
          findings.each do |f|
            ApiAuditAlert.create!(:kind => f['kind'], :subject => f['subject'], :created_on => @now)
          end
        end
      end

      # Successful requests from an IP address that the owner of the
      # credential never used before. Owners without any earlier request
      # are skipped, otherwise every first request would be reported.
      def detect_new_ips
        return unless Setting.api_audit_alert_new_ip?

        first_ids = ApiAuditEvent.succeeded.with_credential.since(@now - NEW_IP_LOOKBACK).where.not(:ip => nil).
                      group(Arel.sql(ApiAuditEvent::CREDENTIAL_OWNER_SQL), :ip).minimum(:id)
        return if first_ids.empty?

        reported = ApiAuditAlert.where(:kind => 'new_ip').pluck(:subject).to_set
        first_ids.each do |(owner_id, ip), first_id|
          next if owner_id.nil?

          owner_id = owner_id.to_i
          subject = "#{owner_id}:#{ip}"
          next if reported.include?(subject)

          notify_new_ip(owner_id, ip, first_id, subject)
        end
      end

      def notify_new_ip(owner_id, ip, first_id, subject)
        return if owner_history?(owner_id, first_id, :ip => ip)
        return unless owner_history?(owner_id, first_id)

        owner = User.active.find_by(:id => owner_id)
        return unless owner

        # The alert is only recorded when the owner was notified, so that a
        # failed delivery is attempted again on the next run
        return unless deliver {Mailer.deliver_api_audit_new_ip(owner, ApiAuditEvent.find(first_id))}

        ApiAuditAlert.create!(:kind => 'new_ip', :subject => subject, :created_on => @now)
      end

      # Returns true if a credential of the owner was used successfully before
      # the event first_id, optionally with additional conditions. Requests
      # made by the owner and requests made as another user are checked with
      # two queries so that each one can use an index.
      def owner_history?(owner_id, first_id, conditions={})
        events = ApiAuditEvent.succeeded.with_credential.where(conditions).
                   where("#{ApiAuditEvent.table_name}.id < ?", first_id)
        events.where(:switched_from_user_id => owner_id).exists? ||
          events.where(:switched_from_user_id => nil, :user_id => owner_id).exists?
      end

      # Runs a mail delivery and logs its failure, so that the remaining
      # recipients are still notified. Returns true if the delivery succeeded.
      def deliver
        yield
        true
      rescue StandardError => e
        @delivery_failed = true
        Rails.logger.error "API audit alert delivery failed: #{e.class}: #{e.message}"
        false
      end
    end
  end
end
