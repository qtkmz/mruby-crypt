MRuby::Gem::Specification.new('mruby-crypt') do |spec|
  spec.license = 'MIT'
  spec.author  = 'qtakamitsu'
  spec.linker.libraries << %w(crypto)
end
