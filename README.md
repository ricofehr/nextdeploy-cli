# nextdeploy-cli

cli commands application for [nextdeploy project](https://github.com/ricofehr/nextdeploy)

A client developed in Ruby allows communication with the rest api via the command line.

## Settings file

A small configuration file is related to the script and must contain the email / password of the user.
An example of /etc/nextdeploy.conf
```
email: userp@os.nextdeploy
password: word123123
endpoint: nextdeploy.local
```

## Install

Please execute "install.sh" bash script.

## Commands

The ruby client manages the following commands
```
ndeploy clone [name]                                # clone project in current folder
ndeploy config [endpoint] [username] [password]     # get/set properties settings for nextdeploy
ndeploy destroy [idvm]                              # destroy a vm
ndeploy details [idvm]                              # Display some details for a vm
ndeploy docker                                      # [BETA] launch containers for execute current project
ndeploy folder [idvm] [workspace]                   # Share project folder from a vm
ndeploy getftp assets|dump|backup [project] [file]  # Get a file from project ftp
ndeploy help [COMMAND]                              # Describe available commands or one specific command
ndeploy launch [name] [branch]                      # Launch a new vm
ndeploy list [--all] [--head n]                     # list launched vms for current user.
ndeploy listftp assets|dump|backup [project]        # List files from project ftp
ndeploy logs [idvm]                                 # Display some logs for a vm
ndeploy projects                                    # list projects for current user
ndeploy putftp assets|dump [project] [file]         # Put a file onto project ftp
ndeploy ssh [idvm]                                  # ssh into a vm
ndeploy sshkey                                      # Put your public ssh key (id_rsa.pub) onto NextDeploy
ndeploy sshkeys                                     # List sshkeys actually associated to the current user
ndeploy up                                          # launch a new vm with current commit (in current folder)
ndeploy upgrade [--force]                           # upgrade ndeploy with the last version
ndeploy version                                     # print current version of ndeploy
```

More specificaly, the "ndeploy docker" subcommand has lot of options available
```
Usage:
  ndeploy docker

Options:
  [--ssh=SSH]
  [--stop=STOP]
  [--rebuild=REBUILD]
  [--reinstall=REINSTALL]
  [--restart=RESTART]
  [--update=UPDATE]
  [--cc=CC]
  [--composersh=COMPOSERSH]
  [--npmsh=NPMSH]
  [--console=CONSOLE]
  [--import=IMPORT]
  [--export=EXPORT]

Description:
  `ndeploy docker` will launch containers for execute current project (in current folder)

  `ndeploy docker --ssh` will ssh into container

  `ndeploy docker --stop` will stop containers for current project

  `ndeploy docker --rebuild` will rebuild (composer, npm, clear caches, ...) current project

  `ndeploy docker --reinstall` will completely reinstall containers for current project

  `ndeploy docker --restart` will restart containers for current project

  `ndeploy docker --update` will execute gitpull and some update commands for current project

  `ndeploy docker --cc` will flush caches for current project

  `ndeploy docker --composersh` will execute "composer install" for current project

  `ndeploy docker --npmsh` will execute javascripts install commands (npm, gulp, grunt) for current project

  `ndeploy docker --console` will execute framework commands (console, drush, wp, ...) for current project

  `ndeploy docker --import` will import datas from NextDeploy ftp repository

  `ndeploy docker --export` will export containers datas to NextDeploy ftp repository
```

## Contributing

1. Fork it.
2. Create your feature branch (`git checkout -b my-new-feature`).
3. Commit your changes (`git commit -am 'Add some feature'`).
4. Push to the branch (`git push origin my-new-feature`).
5. Create new Pull Request.
