# frozen_string_literal: true

SpacemitForumIdentity::Engine.routes.draw do
  get "/credis-forum-identity/bind" => "bindings#show"
  post "/credis-forum-identity/bind" => "bindings#create"
  post "/credis-forum-identity/current-proof" => "bindings#current_proof"
end

Discourse::Application.routes.draw { mount SpacemitForumIdentity::Engine, at: "/" }
