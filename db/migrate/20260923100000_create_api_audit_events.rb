# frozen_string_literal: true

class CreateApiAuditEvents < ActiveRecord::Migration[7.2]
  def change
    create_table :api_audit_events do |t|
      t.datetime :created_on, :null => false
      t.integer :user_id
      t.integer :switched_from_user_id
      t.string :auth_kind, :limit => 16, :null => false
      t.boolean :auth_failed, :null => false, :default => false
      t.integer :personal_access_token_id
      t.integer :oauth_application_id
      t.string :http_method, :limit => 10, :null => false
      t.string :path, :limit => 255, :null => false
      t.integer :status, :null => false
      t.string :ip, :limit => 45
    end
    add_index :api_audit_events, :created_on
    add_index :api_audit_events, [:user_id, :ip]
    add_index :api_audit_events, [:switched_from_user_id, :ip]
    add_index :api_audit_events, [:ip, :created_on]
    add_index :api_audit_events, :personal_access_token_id
  end
end
