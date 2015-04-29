# mvmc-cli

cli commands application for mvmc project (repo here: https://github.com/ricofehr/mvmc)

A client developed in Ruby allows communication with the rest api via the command line. 
A small configuration file is related to the script and must contain the email / password of the user.
An example of /etc/mvmc.conf
```
email: userl@os.mvmc
password: word123123
endpoint: mvmc.local
```

The ruby client manages the following commands
```
`mvmc help` will print help about this command
`mvmc up` launch current commit into vm
`mvmc destroy` destroy current vm associated to this project
`mvmc ssh` ssh into current vm
`mvmc projects` list projects for current user
