# frozen_string_literal: true
source 'https://rubygems.org'

gem 'jekyll'
gem 'jekyll-feed'
gem 'jekyll-seo-tag'
gem 'jekyll-include-cache'
gem "jekyll-theme-chirpy"
gem 'jekyll-admin', group: :jekyll_plugins
group :test do
    gem "html-proofer", "~> 3.18"
end

# Lock jekyll-sass-converter to 2.x on Linux-musl
if RUBY_PLATFORM =~ /linux-musl/
  gem "jekyll-sass-converter", "~> 2.0"
end
