# mvmc-cli

cli commands application for [mvmc project](https://github.com/ricofehr/mvmc)

A client developed in Ruby allows communication with the rest api via the command line.

## Settings file

A small configuration file is related to the script and must contain the email / password of the user.
An example of /etc/mvmc.conf
```
email: userp@os.mvmc
password: word123123
endpoint: mvmc.local
```

## Install

Please execute "install.sh" bash script.

## Commands

The ruby client manages the following commands
```
`  mvmc clone [projectname]                      # clone project in current folder
`  mvmc config [endpoint] [username] [password]  # get/set properties settings for mvmc
`  mvmc destroy                                  # destroy current vm
`  mvmc getftp assets|dump [project]             # get an assets archive or a dump for the [project]
`  mvmc git [cmd]                                # Executes a git command
`  mvmc help [COMMAND]                           # Describe available commands or one specific command
`  mvmc launch [projectname] [branch] [commit]   # launch [commit] (default is head) on the [branch] (default is master) for [projectname] into remote mvmc
`  mvmc list                                     # list launched vms for current user
`  mvmc listftp assets|dump [project]            # list assets archive or a dump for the [project]
`  mvmc projects                                 # list projects for current user
`  mvmc putftp assets|dump [project] [file]      # putftp an assets archive [file] or a dump [file] for the [project]
`  mvmc ssh                                      # ssh into remote vm
`  mvmc up                                       # launch current commit to remote mvmc
```

## Contributing

1. Fork it.
2. Create your feature branch (`git checkout -b my-new-feature`).
3. Commit your changes (`git commit -am 'Add some feature'`).
4. Push to the branch (`git push origin my-new-feature`).
5. Create new Pull Request.
