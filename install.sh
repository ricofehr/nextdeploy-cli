#!/bin/bash
#
# Install instruction for cli cmd
# @author Eric Fehr (eric.fehr@publicis-modem.fr, @github: ricofehr)

# install the cli cmd into the operating system
install-cli() {
  # if ubuntu / debian, install ruby package if needed
  if [[ -f /etc/debian_version ]]; then
    whereis gem || sudo apt-get install -y --force-yes ruby rubygems
  fi

  sudo gem install bundler >install.log 2>&1
  bundle install >install.log 2>&1
  chmod +x mvmc.rb
  if [[ -d /usr/local/bin ]]; then
    sudo cp mvmc.rb /usr/bin/mvmc
  else
    sudo cp mvmc.rb /usr/bin/mvmc
  fi
}

# generate default setting file and give instructions to change this ones
default-settings() {
  echo "endpoint: mvmc.local" > ~/.mvmc.conf
  echo "email: userd@os.mvmc" >> ~/.mvmc.conf
  echo "password: word123123" >> ~/.mvmc.conf
}

# msg to end install
end-msg() {
  echo "Installation is complete"
  mvmc
  echo "Default settings"
  mvmc config
  echo "You can change default values with: mvmc config [endpoint] [email] [password]"
}

install-cli
default-settings
end-msg