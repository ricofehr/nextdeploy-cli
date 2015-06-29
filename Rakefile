require 'rubygems'
require 'bundler/setup' # Releasy requires require that your application uses bundler.
require 'releasy'

#<<<
Releasy::Project.new do
  name "MVMC Cli"
  version "0.9"
  verbose # Can be removed if you don't want to see all build messages.
  executable "mvmc.rb"
  #files "lib/**/*.rb", "config/**/*.yml", "media/**/*.*"
#  exposed_files "README.md", "LICENSE"
  #add_link "https://github.", "Mvmc webui"
  exclude_encoding # Applications that don't use advanced encoding (e.g. Japanese characters) can save build size with this.

  # Create a variety of releases, for all platforms.
  add_build :osx_app do
    url "https://github.com/ricofehr/mvmc-cli"
    wrapper "wrapper/gosu-mac-wrapper-0.7.44.tar.gz" # Assuming this is where you downloaded this file.
  #  icon "media/mvmc.icns"
    add_package :dmg
  end

end
#>>>
