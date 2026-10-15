# frozen_string_literal: true

RSpec.describe SpacemitForumIdentity::BindingsController do
  fab!(:user) { Fabricate(:user, active: true, approved: true) }

  describe "#current_proof" do
    it "rejects client identity supplied through HTTP forwarding headers" do
      ENV["CREDIS_FORUM_IDENTITY_ENABLED"] = "false"
      post "/credis-forum-identity/current-proof.json", params: { forum_user_id: user.id }, headers: { "X-Forwarded-Client-Cert" => "synthetic" }
      expect(response.status).to eq(404)
      expect(DB.query_single("SELECT count(*) FROM credis_identity_associations").first).to eq(0)
    ensure
      ENV["CREDIS_FORUM_IDENTITY_ENABLED"] = "false"
    end
  end

  describe "#create" do
    it "keeps disabled binding inaccessible even to a signed-in user" do
      sign_in(user)
      post "/credis-forum-identity/bind.json", params: { handle: "a" * 43 }
      expect(response.status).to eq(404)
      expect(DB.query_single("SELECT count(*) FROM credis_identity_associations").first).to eq(0)
    end
  end
end

RSpec.describe UserAssociatedAccount do
  fab!(:user) { Fabricate(:user, active: true, approved: true) }
  let(:uuid) { "8f14e45f-ceea-4c1f-8f14-e45fceea4c1f" }

  describe "certified identity persistence" do
    it "rejects callback-bypassing reassignment and retains normal foreign-provider deletion" do
      association = UserAssociatedAccount.create!(provider_name: "oauth2_basic", provider_uid: uuid, user: user, last_used: Time.now)
      DB.exec("SELECT register_credis_identity_association(:id,7,'test-platform',CAST(:uuid AS uuid),:user)", id: association.id, uuid: uuid, user: user.id)
      expect do
        UserAssociatedAccount.transaction(requires_new: true) { association.update_columns(provider_uid: "9f14e45f-ceea-4c1f-8f14-e45fceea4c1f") }
      end.to raise_error(ActiveRecord::StatementInvalid)
      expect(association.reload.provider_uid).to eq(uuid)
      foreign = UserAssociatedAccount.create!(provider_name: "other", provider_uid: "test", user: user, last_used: Time.now)
      expect { foreign.destroy! }.to change { UserAssociatedAccount.where(id: foreign.id).count }.from(1).to(0)
    end
  end
end
