# frozen_string_literal: true

class ProtectCredisForumIdentityAssociations < ActiveRecord::Migration[8.0]
  def up
    execute <<~SQL
      CREATE TABLE credis_identity_associations (
        association_id bigint PRIMARY KEY REFERENCES user_associated_accounts(id),
        instance_id bigint NOT NULL CHECK (instance_id>0),
        platform_id text NOT NULL CHECK (length(btrim(platform_id)) BETWEEN 1 AND 255),
        provider_uid uuid NOT NULL,
        user_id bigint NOT NULL CHECK (user_id>0),
        created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
        UNIQUE(instance_id,platform_id,provider_uid),
        UNIQUE(instance_id,user_id)
      );
      CREATE FUNCTION protect_credis_identity_association() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        RAISE EXCEPTION 'certified forum identity association is immutable';
      END;
      $$;
      CREATE TRIGGER credis_identity_associations_immutable BEFORE UPDATE OR DELETE ON credis_identity_associations
        FOR EACH ROW EXECUTE FUNCTION protect_credis_identity_association();
      CREATE TRIGGER credis_identity_associations_no_truncate BEFORE TRUNCATE ON credis_identity_associations
        FOR EACH STATEMENT EXECUTE FUNCTION protect_credis_identity_association();
      CREATE FUNCTION guard_credis_source_association() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF TG_OP='TRUNCATE' THEN
          IF EXISTS(SELECT 1 FROM credis_identity_associations) THEN RAISE EXCEPTION 'certified forum identity association is immutable'; END IF;
          RETURN NULL;
        END IF;
        IF EXISTS(SELECT 1 FROM credis_identity_associations WHERE association_id=OLD.id) THEN
          IF TG_OP='DELETE' OR NEW.id IS DISTINCT FROM OLD.id OR NEW.user_id IS DISTINCT FROM OLD.user_id
            OR NEW.provider_name IS DISTINCT FROM OLD.provider_name OR NEW.provider_uid IS DISTINCT FROM OLD.provider_uid THEN
            RAISE EXCEPTION 'certified forum identity association is immutable';
          END IF;
        END IF;
        IF TG_OP='DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
      END;
      $$;
      CREATE TRIGGER user_associated_accounts_credis_identity_guard BEFORE UPDATE OR DELETE ON user_associated_accounts
        FOR EACH ROW EXECUTE FUNCTION guard_credis_source_association();
      CREATE TRIGGER user_associated_accounts_credis_no_truncate BEFORE TRUNCATE ON user_associated_accounts
        FOR EACH STATEMENT EXECUTE FUNCTION guard_credis_source_association();
      CREATE FUNCTION register_credis_identity_association(p_association bigint,p_instance bigint,p_platform text,p_uuid uuid,p_user bigint)
      RETURNS void LANGUAGE plpgsql AS $$
      DECLARE source user_associated_accounts%ROWTYPE; saved credis_identity_associations%ROWTYPE;
      BEGIN
        IF p_association IS NULL OR p_association<=0 OR p_instance IS NULL OR p_instance<=0
          OR p_user IS NULL OR p_user<=0 OR p_platform IS NULL OR length(btrim(p_platform))=0
          OR p_uuid IS NULL OR p_uuid='00000000-0000-0000-0000-000000000000'::uuid THEN
          RAISE EXCEPTION 'forum association registration rejected';
        END IF;
        SELECT * INTO source FROM user_associated_accounts WHERE id=p_association FOR UPDATE;
        IF NOT FOUND OR source.provider_name<>'oauth2_basic' OR source.provider_uid<>p_uuid::text OR source.user_id<>p_user THEN
          RAISE EXCEPTION 'forum association registration rejected';
        END IF;
        SELECT * INTO saved FROM credis_identity_associations WHERE association_id=p_association;
        IF FOUND THEN
          IF saved.instance_id=p_instance AND saved.platform_id=p_platform AND saved.provider_uid=p_uuid AND saved.user_id=p_user THEN RETURN; END IF;
          RAISE EXCEPTION 'forum association registration conflict';
        END IF;
        INSERT INTO credis_identity_associations(association_id,instance_id,platform_id,provider_uid,user_id)
          VALUES(p_association,p_instance,p_platform,p_uuid,p_user);
      END;
      $$;
      REVOKE ALL ON credis_identity_associations FROM PUBLIC;
      REVOKE EXECUTE ON FUNCTION register_credis_identity_association(bigint,bigint,text,uuid,bigint),
        protect_credis_identity_association(),guard_credis_source_association() FROM PUBLIC;
    SQL
  end

  def down
    raise ActiveRecord::IrreversibleMigration, "Identity association evidence must be retained"
  end
end
