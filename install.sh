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

  if [[ -f /usr/bin/sw_vers ]]; then
    install_xcode_osx
  fi

  gem install bundler >install.log 2>&1
  bundle install >>install.log 2>&1
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

# Cmdline xcode tools install
install_xcode_osx() {
  if [[ ! -d /Library/Developer/CommandLineTools ]]; then
    echo "CommandLineTools Installation ..."
    /bin/bash -c 'xcode-select --install'
    #wait install is finish
    while [[ ! -d /Library/Developer/CommandLineTools ]]; do
      echo "wait 5s ...."
      sleep 5
    done
  fi

  sudo /bin/bash -c 'xcode-select -switch /Library/Developer/CommandLineTools'
  (($?!=0)) && echo 'Xcode CommandLineTools has failed'
}

install-cli
default-settings
end-msg
