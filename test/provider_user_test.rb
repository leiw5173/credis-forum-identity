# frozen_string_literal: true

require "json"
require_relative "../lib/spacemit_forum_identity/provider_user"

valid = '{"code":200,"msg":"ok","data":{"id":"8f14e45f-ceea-4c1f-8f14-e45fceea4c1f","username":"fixture","email":"fixture@example.invalid","status":"1","authCenterEmail":"not-used@example.invalid"}}'
subject = SpacemitForumIdentity::ProviderUser.parse(valid)
raise "wrong provider identity" unless subject == {
  uuid: "8f14e45f-ceea-4c1f-8f14-e45fceea4c1f",
  username: "fixture",
  email: "fixture@example.invalid",
  email_verified: false,
}
[
  valid.sub('"code":200', '"code":500'),
  valid.sub('"status":"1"', '"status":"0"'),
  valid.sub('"status":"1"', '"status":1'),
  valid.sub('"status":"1"', '"status":null'),
  valid.sub('"status":"1"', '"status":"1","status":"0"'),
  valid.sub('"email":"fixture@example.invalid",', ''),
  valid.sub('"id":"8f14e45f-ceea-4c1f-8f14-e45fceea4c1f"', '"id":42'),
  valid.sub('8f14e45f-ceea-4c1f-8f14-e45fceea4c1f', '00000000-0000-0000-0000-000000000000'),
  valid.sub('"email":"fixture@example.invalid"', '"email":"Name <fixture@example.invalid>"'),
  valid + '{}',
  'x' * 65_537,
].each_with_index do |raw, index|
  begin
    SpacemitForumIdentity::ProviderUser.parse(raw)
    raise "invalid provider response accepted: #{index}"
  rescue SpacemitForumIdentity::ProviderUser::Rejected
  end
end
observations = []
[{}, { "email_verified" => true }, { "email_verified" => false }, { "email_verified" => "private-value" }].each do |extra|
  raw = JSON.parse(valid)
  raw["data"].merge!(extra)
  result = SpacemitForumIdentity::ProviderUser.parse(JSON.generate(raw)) { |metadata| observations << metadata }
  raise "probe changed activation policy" unless result[:email_verified] == false
end
raise "missing probe observations" unless observations == [
  { present: false, type: "absent", strictly_true: false },
  { present: true, type: "boolean", strictly_true: true },
  { present: true, type: "boolean", strictly_true: false },
  { present: true, type: "string", strictly_true: false },
]
raise "probe leaked response" if JSON.generate(observations).include?("private-value")
puts "Ruby strict provider identity tests PASS"
