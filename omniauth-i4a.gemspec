# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth-i4a/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-i4a"
  spec.version       = Omniauth::I4a::VERSION
  spec.authors       = ["Dave Sloan"]
  spec.email         = ["dsloan@blueskyelearn.com"]
  spec.summary       = %q{I4A Omniauth Gem}
  spec.description   = %q{I4A Ominauth gem using oauth2 specs}
  spec.homepage      = "https://github.com/blueskybroadcast/omniauth-i4a"
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency 'omniauth', '~> 1.0'
  spec.add_dependency 'omniauth-oauth2', '~> 1.0'
  spec.add_dependency 'typhoeus'

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake"
end
