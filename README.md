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
```

## Build dmg package
1. Install 7z command
```
brew install p7zip
```
2. Create wrapper folder (at the same level than mvmc.rb)
```
mkdir wrapper
```
3. Download wrapper into this folder
```
cd wrapper && wget https://www.libgosu.org/downloads/gosu-mac-wrapper-0.7.44.tar.gz 
```
4. Execute the rake command
```
rake package:osx:app:dmg
```

## Contributing

1. Fork it.
2. Create your feature branch (`git checkout -b my-new-feature`).
3. Commit your changes (`git commit -am 'Add some feature'`).
4. Push to the branch (`git push origin my-new-feature`).
5. Create new Pull Request.
