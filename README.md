# mvmc-cli

cli commands application for [mvmc project](https://github.com/ricofehr/mvmc)

You can download dmg package file [here](http://dmg.mvmc.services-pm.fr/)

A client developed in Ruby allows communication with the rest api via the command line. 
A small configuration file is related to the script and must contain the email / password of the user.
An example of /etc/mvmc.conf
```
email: userl@os.mvmc
password: word123123
endpoint: mvmc.local
```

Please execute "bundle install" after the clone

The ruby client manages the following commands
```
`mvmc help` will print help about this command
`mvmc up` launch current commit into vm
`mvmc destroy` destroy current vm associated to this project
`mvmc ssh` ssh into current vm
`mvmc projects` list projects for current user
`mvmc clone [project-name]` clone project in current folder
`mvmc config [endpoint] [username] [password]` get/set properties settings for mvmc
```

## Contributing

1. Fork it.
2. Create your feature branch (`git checkout -b my-new-feature`).
3. Commit your changes (`git commit -am 'Add some feature'`).
4. Push to the branch (`git push origin my-new-feature`).
5. Create new Pull Request.
