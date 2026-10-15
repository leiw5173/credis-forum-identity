# frozen_string_literal: true

class AllowPendingCredisEnrollmentProofRotation < ActiveRecord::Migration[8.0]
  def up
    execute <<~SQL
      CREATE OR REPLACE FUNCTION protect_credis_enrollment_identity() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF TG_OP='DELETE' OR NEW.association_id IS DISTINCT FROM OLD.association_id OR OLD.status='delivered'
          OR NEW.status NOT IN ('pending','delivered') OR (NEW.status='pending' AND NEW.delivered_at IS NOT NULL)
          OR (NEW.status='delivered' AND NEW.delivered_at IS NULL) THEN
          RAISE EXCEPTION 'forum enrollment evidence is immutable';
        END IF;
        RETURN NEW;
      END;
      $$;
    SQL
  end

  def down
    raise ActiveRecord::IrreversibleMigration, "Delivered forum enrollment evidence must remain immutable"
  end
end
