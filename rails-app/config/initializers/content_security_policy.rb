# frozen_string_literal: true

Rails.application.configure do
  config.content_security_policy do |policy|
    policy.default_src :self
    policy.base_uri    :self
    policy.font_src    :self, :data
    policy.img_src     :self, :data
    policy.object_src  :none
    policy.script_src  :self
    policy.style_src   :self, :unsafe_inline
    policy.form_action :self,
                       'http://localhost:9000', 'http://localhost:3000', 'http://localhost:8080',
                       'http://127.0.0.1:9000', 'http://127.0.0.1:3000', 'http://127.0.0.1:8080',
                       'http://host.docker.internal:9000', 'http://host.docker.internal:3000', 'http://host.docker.internal:8080'
    policy.frame_ancestors :none
  end
end
