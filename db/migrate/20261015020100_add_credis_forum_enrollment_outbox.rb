# frozen_string_literal: true

class AddCredisForumEnrollmentOutbox < ActiveRecord::Migration[8.0]
  def up
    execute <<~SQL
      CREATE TABLE credis_identity_enrollment_outbox (
        association_id bigint PRIMARY KEY REFERENCES credis_identity_associations(association_id),
        assertion jsonb NOT NULL,
        assertion_sha256 text NOT NULL CHECK(assertion_sha256~'^[0-9a-f]{64}$'),
        status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','delivered')),
        attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0),
        next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
        delivered_at timestamptz,
        created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
        CHECK((status='pending' AND delivered_at IS NULL) OR (status='delivered' AND delivered_at IS NOT NULL))
      );
      CREATE FUNCTION protect_credis_enrollment_identity() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF TG_OP='DELETE' OR NEW.association_id IS DISTINCT FROM OLD.association_id
          OR NEW.assertion IS DISTINCT FROM OLD.assertion OR NEW.assertion_sha256 IS DISTINCT FROM OLD.assertion_sha256
          OR OLD.status='delivered' THEN RAISE EXCEPTION 'forum enrollment evidence is immutable'; END IF;
        RETURN NEW;
      END;
      $$;
      CREATE TRIGGER credis_identity_enrollment_outbox_guard BEFORE UPDATE OR DELETE ON credis_identity_enrollment_outbox
        FOR EACH ROW EXECUTE FUNCTION protect_credis_enrollment_identity();
      CREATE TRIGGER credis_identity_enrollment_outbox_no_truncate BEFORE TRUNCATE ON credis_identity_enrollment_outbox
        FOR EACH STATEMENT EXECUTE FUNCTION protect_credis_identity_association();
      REVOKE ALL ON credis_identity_enrollment_outbox FROM PUBLIC;
      REVOKE EXECUTE ON FUNCTION protect_credis_enrollment_identity() FROM PUBLIC;
    SQL
  end

  def down
    raise ActiveRecord::IrreversibleMigration, "Forum enrollment evidence must be retained"
  end
end
