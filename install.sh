#!/bin/bash
#
# Install instruction for cli cmd
# @author Eric Fehr (ricofehr@nextdeploy.io, @github: ricofehr)

# flag who decide if it's the first install
NEWINSTALL=1

# install the cli cmd into the operating system
install-cli() {
  [[ -f /usr/bin/nextdeploy ]] && NEWINSTALL=0
  [[ -f /usr/local/bin/nextdeploy ]] && NEWINSTALL=0

  if (( NEWINSTALL == 1 )); then
    # if ubuntu / debian, install ruby package if needed
    if [[ -f /etc/debian_version ]]; then
      whereis gem || sudo apt-get install -y --force-yes ruby rubygems
      sudo apt-get install -y --force-yes ruby-dev
      sudo gem install bundler >install.log 2>&1
    fi

    # fedora, install ruby package if needed
    if [[ -f /etc/fedora_release ]]; then
      whereis gem || sudo dnf install -y ruby rubygems
      sudo dnf install -y ruby-dev
      gem install bundler >install.log 2>&1
    fi

    # for macos, install xcode
    if [[ -f /usr/bin/sw_vers ]]; then
      install_xcode_osx
      sudo gem install bundler >install.log 2>&1
    fi
  fi

  bundle install >>install.log 2>&1
  chmod +x nextdeploy.rb
  if [[ -d /usr/local/bin ]] && [[ ! -f /usr/bin/nextdeploy ]]; then
    sudo cp nextdeploy.rb /usr/local/bin/nextdeploy
    pushd /usr/local/bin >/dev/null
    sudo ln -sf nextdeploy ndeploy
    popd >/dev/null
  else
    sudo cp nextdeploy.rb /usr/bin/nextdeploy
    pushd /usr/bin >/dev/null
    sudo ln -sf nextdeploy ndeploy
    popd >/dev/null
  fi
}

# generate default setting file and give instructions to change this ones
default-settings() {
  echo "endpoint: api.nextdeploy.local" > ~/.nextdeploy.conf
  echo "email: userd@os.nextdeploy" >> ~/.nextdeploy.conf
  echo "password: word123123" >> ~/.nextdeploy.conf
}

# msg to end install
end-msg() {
  echo "Installation is complete, ndeploy version $(ndeploy version)"
  ndeploy
  echo "Settings"
  ndeploy config
  echo "You can change this values with: ndeploy config [endpoint] [email] [password]"
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
(( NEWINSTALL == 1 )) && default-settings
end-msg
