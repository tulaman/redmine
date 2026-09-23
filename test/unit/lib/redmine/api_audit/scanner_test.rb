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

require_relative '../../../../test_helper'

class Redmine::ApiAudit::ScannerTest < ActiveSupport::TestCase
  def setup
    @now = Time.now.change(:usec => 0)
    ActionMailer::Base.deliveries.clear
  end

  def create_event(attributes={})
    ApiAuditEvent.create!({:auth_kind => 'api_key', :user_id => 2, :http_method => 'GET', :path => '/issues.json',
                           :status => 200, :ip => '10.0.0.1', :created_on => @now - 1.minute}.merge(attributes))
  end

  def create_failures(count, ip='10.0.0.9', created_on=@now - 1.minute)
    count.times do
      create_event(:auth_failed => true, :user_id => nil, :status => 401, :ip => ip, :created_on => created_on)
    end
  end

  def scan(settings={}, now=@now)
    defaults = {:api_audit_log_enabled => '1', :api_audit_alert_failures_threshold => '3',
                :api_audit_alert_volume_threshold => '3', :api_audit_alert_new_ip => '1'}
    with_settings(defaults.merge(settings)) do
      Redmine::ApiAudit::Scanner.new(:now => now).run
    end
  end

  def text_part(mail)
    mail.parts.detect {|part| part.mime_type == 'text/plain'}.body.decoded
  end

  def admin_emails
    User.active.where(:admin => true).map(&:mail).sort
  end

  def delivered_to
    ActionMailer::Base.deliveries.flat_map(&:to).sort
  end

  def test_run_should_do_nothing_when_auditing_is_disabled
    create_failures(3)
    assert scan(:api_audit_log_enabled => '0')
    assert_empty ActionMailer::Base.deliveries
  end

  def test_failures_should_notify_admins
    create_failures(3)
    assert scan
    assert_equal admin_emails, delivered_to
    assert_mail_body_match '10.0.0.9', ActionMailer::Base.deliveries.last
    assert ApiAuditAlert.exists?(:kind => 'failures', :subject => '10.0.0.9')
  end

  def test_failures_below_threshold_should_not_notify
    create_failures(2)
    scan
    assert_empty ActionMailer::Base.deliveries
  end

  def test_failures_outside_window_should_not_notify
    create_failures(3, '10.0.0.9', @now - 11.minutes)
    scan
    assert_empty ActionMailer::Base.deliveries
  end

  def test_failures_should_not_notify_twice
    create_failures(3)
    scan
    ActionMailer::Base.deliveries.clear
    scan
    assert_empty ActionMailer::Base.deliveries
  end

  def test_failures_should_notify_again_after_repeat_interval
    create_failures(3)
    scan
    ActionMailer::Base.deliveries.clear
    create_failures(3, '10.0.0.9', @now + 60.minutes)
    scan({}, @now + 61.minutes)
    assert_equal admin_emails, delivered_to
    assert_equal 2, ApiAuditAlert.where(:kind => 'failures', :subject => '10.0.0.9').count
  end

  def test_many_failing_ips_should_be_sent_in_one_truncated_digest
    25.times {|i| create_failures(3, "10.0.1.#{i + 1}")}
    assert scan
    assert_equal admin_emails, delivered_to
    text = text_part(ActionMailer::Base.deliveries.last)
    assert_equal 20, text.scan(/10\.0\.1\.\d+: 3/).size
    assert_include 'and 5 more', text
    assert_equal 25, ApiAuditAlert.where(:kind => 'failures').count
  end

  def test_failures_and_volume_should_be_sent_in_one_digest
    create_failures(3)
    3.times {create_event(:user_id => 2)}
    assert scan(:api_audit_alert_new_ip => '0')
    assert_equal admin_emails, delivered_to
    mail = ActionMailer::Base.deliveries.last
    assert_mail_body_match '10.0.0.9: 3', mail
    assert_mail_body_match 'jsmith: 3', mail
    assert_mail_body_match 'Failed API authentications per IP address in the last 10 minutes', mail
    assert_mail_body_match 'API requests per user in the last 60 minutes', mail
  end

  def test_delivery_failure_should_not_stop_other_recipients
    other_admin = User.generate!(:admin => true)
    create_failures(3)
    Mailer.stubs(:deliver_api_audit_digest).with(User.find(1), anything, anything).raises(RuntimeError, 'smtp down')
    Mailer.expects(:deliver_api_audit_digest).with(other_admin, anything, anything).once
    assert_equal false, scan
    assert ApiAuditAlert.exists?(:kind => 'failures', :subject => '10.0.0.9')
  end

  def test_digest_should_not_be_recorded_when_every_delivery_fails
    create_failures(3)
    Mailer.stubs(:deliver_api_audit_digest).raises(RuntimeError, 'smtp down')
    assert_equal false, scan
    assert_equal 0, ApiAuditAlert.count
  end

  def test_new_ip_should_be_retried_when_delivery_fails
    create_event(:ip => '10.0.0.1', :created_on => @now - 2.days)
    create_event(:ip => '10.0.0.2')
    Mailer.stubs(:deliver_api_audit_new_ip).raises(RuntimeError, 'smtp down')
    assert_equal false, scan(:api_audit_alert_volume_threshold => '0')
    assert_not ApiAuditAlert.exists?(:kind => 'new_ip')
    Mailer.unstub(:deliver_api_audit_new_ip)
    assert scan(:api_audit_alert_volume_threshold => '0')
    assert_equal ['jsmith@somenet.foo'], delivered_to
    assert ApiAuditAlert.exists?(:kind => 'new_ip', :subject => '2:10.0.0.2')
  end

  def test_failures_detector_disabled_by_zero_threshold
    create_failures(3)
    scan(:api_audit_alert_failures_threshold => '0')
    assert_empty ActionMailer::Base.deliveries
  end

  def test_volume_should_notify_admins
    3.times {create_event(:user_id => 2)}
    scan(:api_audit_alert_new_ip => '0')
    assert_equal admin_emails, delivered_to
    assert_mail_body_match 'jsmith', ActionMailer::Base.deliveries.last
    ActionMailer::Base.deliveries.clear
    scan(:api_audit_alert_new_ip => '0')
    assert_empty ActionMailer::Base.deliveries
  end

  def test_volume_should_ignore_failed_events
    3.times {create_event(:user_id => 2, :auth_failed => true, :status => 401)}
    scan(:api_audit_alert_failures_threshold => '0', :api_audit_alert_new_ip => '0')
    assert_empty ActionMailer::Base.deliveries
  end

  def test_volume_of_deleted_user_should_show_the_user_id
    3.times {create_event(:user_id => 999)}
    scan(:api_audit_alert_new_ip => '0')
    assert_mail_body_match '#999: 3', ActionMailer::Base.deliveries.last
  end

  def test_new_ip_should_notify_with_history_inside_lookback
    create_event(:ip => '10.0.0.1', :created_on => @now - 2.hours)
    create_event(:ip => '10.0.0.2')
    scan(:api_audit_alert_volume_threshold => '0')
    assert_equal ['jsmith@somenet.foo'], delivered_to
    assert_mail_body_match '10.0.0.2', ActionMailer::Base.deliveries.last
  end

  def test_new_ip_should_ignore_known_ip_inside_lookback
    create_event(:ip => '10.0.0.2', :created_on => @now - 2.hours)
    create_event(:ip => '10.0.0.2')
    scan(:api_audit_alert_volume_threshold => '0')
    assert_empty ActionMailer::Base.deliveries
  end

  def test_new_ip_should_notify_credential_owner
    create_event(:ip => '10.0.0.1', :created_on => @now - 2.days)
    create_event(:ip => '10.0.0.2')
    scan(:api_audit_alert_volume_threshold => '0')
    assert_equal ['jsmith@somenet.foo'], delivered_to
    assert_mail_body_match '10.0.0.2', ActionMailer::Base.deliveries.last
    ActionMailer::Base.deliveries.clear
    scan(:api_audit_alert_volume_threshold => '0')
    assert_empty ActionMailer::Base.deliveries
  end

  def test_new_ip_should_ignore_user_without_history
    create_event(:ip => '10.0.0.2')
    scan(:api_audit_alert_volume_threshold => '0')
    assert_empty ActionMailer::Base.deliveries
  end

  def test_new_ip_should_ignore_known_ip
    create_event(:ip => '10.0.0.2', :created_on => @now - 2.days)
    create_event(:ip => '10.0.0.2')
    scan(:api_audit_alert_volume_threshold => '0')
    assert_empty ActionMailer::Base.deliveries
  end

  def test_new_ip_should_ignore_anonymous_requests
    create_event(:auth_kind => 'none', :user_id => nil, :ip => '10.0.0.1', :created_on => @now - 2.days)
    create_event(:auth_kind => 'none', :user_id => nil, :ip => '10.0.0.2')
    scan(:api_audit_alert_volume_threshold => '0')
    assert_empty ActionMailer::Base.deliveries
  end

  def test_new_ip_detector_can_be_disabled
    create_event(:ip => '10.0.0.1', :created_on => @now - 2.days)
    create_event(:ip => '10.0.0.2')
    scan(:api_audit_alert_volume_threshold => '0', :api_audit_alert_new_ip => '0')
    assert_empty ActionMailer::Base.deliveries
  end

  def test_new_ip_with_switch_user_should_notify_the_admin_who_authenticated
    create_event(:user_id => 1, :ip => '10.0.0.1', :created_on => @now - 2.days)
    create_event(:user_id => 3, :switched_from_user_id => 1, :ip => '10.0.0.2')
    scan(:api_audit_alert_volume_threshold => '0')
    assert_equal ['admin@somenet.foo'], delivered_to
  end

  def test_failing_detector_should_not_stop_the_others
    Redmine::ApiAudit::Scanner.any_instance.stubs(:detect_failures).raises(RuntimeError, 'boom')
    3.times {create_event(:user_id => 2)}
    assert_equal false, scan(:api_audit_alert_new_ip => '0')
    assert_equal admin_emails, delivered_to
  end
end
