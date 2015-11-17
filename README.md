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
`  ndeploy clone [projectname]                         # clone project in current folder
`  ndeploy config [endpoint] [username] [password]     # get/set properties settings for nextdeploy
`  ndeploy destroy                                     # destroy current vm
`  ndeploy getftp assets|dump [project]                # get an assets archive or a dump for the [project]
`  ndeploy git [cmd]                                   # Executes a git command
`  ndeploy help [COMMAND]                              # Describe available commands or one specific command
`  ndeploy launch [projectname] [branch] [commit]      # launch [commit] (default is head) on the [branch] (default is master) for [projectname] into remote nextdeploy platform
`  ndeploy list                                        # list launched vms for current user
`  ndeploy listftp assets|dump [project]               # list assets archive or a dump for the [project]
`  ndeploy projects                                    # list projects for current user
`  ndeploy putftp assets|dump [project] [file]         # putftp an assets archive [file] or a dump [file] for the [project]
`  ndeploy ssh                                         # ssh into remote vm
`  ndeploy up                                          # launch current commit to remote nextdeploy
```

## Contributing

1. Fork it.
2. Create your feature branch (`git checkout -b my-new-feature`).
3. Commit your changes (`git commit -am 'Add some feature'`).
4. Push to the branch (`git push origin my-new-feature`).
5. Create new Pull Request.
