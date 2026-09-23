# frozen_string_literal: true

class CreateApiAuditAlerts < ActiveRecord::Migration[7.2]
  def change
    create_table :api_audit_alerts do |t|
      t.string :kind, :limit => 16, :null => false
      t.string :subject, :limit => 255, :null => false
      t.datetime :created_on, :null => false
    end
    add_index :api_audit_alerts, [:kind, :subject, :created_on]
  end
end
