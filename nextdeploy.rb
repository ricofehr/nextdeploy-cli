#!/usr/bin/env ruby
# encoding: utf-8
# shell: /bin/bash
#
# CommandLine tool for NextDeploy project (http://nextdeploy.io)
# @author Eric Fehr (ricofehr@nextdeploy.io, @github: ricofehr)

require 'thor'
require 'faraday'
require 'active_support'
require 'active_support/core_ext'
require 'uri'
require 'socket'
require 'open-uri'
require 'net/ftp'
require 'socket'
require 'timeout'

class NextDeploy < Thor
  # Create docker stack for current project folder
  #
  desc "docker", "[BETA] launch containers for execute current project"
  long_desc <<-LONGDESC
  'ndeploy docker' ensures that containers are running for execute current project\n
  Following options are available\n
                  --ssh will ssh into container\n
                  --stop will stop containers for current project\n
                  --destroy will destroy containers for current project\n
                  --rebuild will rebuild (composer, npm, clear caches, ...) current project\n
                  --reinstall will completely reinstall containers for current project\n
                  --restart will restart containers for current project\n
                  --update will execute gitpull and some update commands for current project\n
                  --cc will flush caches for current project\n
                  --composersh will execute "composer install" for current project\n
                  --npmsh will execute javascripts install commands (npm, gulp, grunt) for current project\n
                  --console will execute framework commands (console, drush, wp, ...) for current project\n
                  --import will import datas from NextDeploy ftp repository\n
                  --export will export containers datas to NextDeploy ftp repository\n
                  --sql will connect to mysql database\n
                  --mongo will connect to mongo database\n
                  --pma will launch phpmyadmin container for mysql database interaction\n
  LONGDESC
  option :ssh
  option :stop
  option :rebuild
  option :reinstall
  option :restart
  option :destroy
  option :update
  option :cc
  option :composersh
  option :npmsh
  option :console
  option :import
  option :export
  option :sql
  option :mongo
  option :pma
  def docker
    # check folder => root of project
    init

    # ensure requirements
    unless @project
      warn("Git repository for #{gitpath} not found, have-you already import project ?")
      warn("Please execute ndeploy clone first and go at the root of the project")
      exit
    end

    unless Dir.exists?('.git')
      warn("No .git folder, please go at the root of your project")
      exit
    end

    # check if docker is already install
    docker_check

    # init destroy flags
    isdestroy = options[:reinstall] || options[:destroy] ? true : false

    # if reinstall or restart, ensure containers are stopped before up
    docker_compose_stop(isdestroy) if options[:restart] || options[:reinstall]
    # generate container if needed
    docker_compose_gen
    # ensure container are running
    docker_compose_up

    # execute action follow options parameters
    docker_import if options[:import]
    docker_export if options[:export]
    docker_composersh(false) if options[:composersh]
    docker_npmsh(false) if options[:npmsh]
    docker_update if options[:update]
    docker_rebuild if options[:rebuild]
    docker_console if options[:console]
    docker_cc if options[:cc]
    docker_compose_stop(isdestroy) if options[:stop]
    docker_compose_stop(isdestroy) if options[:destroy]
    docker_list_endpoints unless options[:destroy] || options[:stop]
    docker_pma if options[:pma]
    docker_ssh if options[:ssh]
    docker_sql if options[:sql]
    docker_mongo if options[:mongo]
  end

  # Print current version
  #
  desc "version", "print current version of ndeploy"
  def version
    init_constants
    puts "Version: #{@@version}"

    remote_version = get_remote_version
    if remote_version.eql? @@version
      puts "You have the last version of ndeploy. Your system is uptodate."
    else
      puts "A new version of ndeploy is available. We recommend to upgrade it: ndeploy upgrade"
    end
  end

  # alias "update" for upgrade command
  map 'update' => :upgrade

  # upgrade ndeploy
  #
  desc "upgrade [--force]", "upgrade ndeploy with the last version"
  long_desc <<-LONGDESC
    `ndeploy upgrade` upgrade ndeploy with the last version if needed\n
    `ndeploy upgrade --force` reinstall ndeploy with last version\n
  LONGDESC
  option :force
  def upgrade
    init_constants
    remote_version = get_remote_version
    if options[:force]
      exec "curl -sSL http://cli.nextdeploy.io/ | bash"
    elsif remote_version.eql? @@version
      puts "You have already the last version of ndeploy. No need to upgrade"
    else
      exec "curl -sSL http://cli.nextdeploy.io/ | bash"
    end
  end

  # Launch current commit into a new vms on nextdeploy cloud
  #
  desc "up", "launch a new vm with current commit (in current folder)"
  long_desc <<-LONGDESC
    `ndeploy up` launch a new vm with current commit. So, this command checks that we are into a project folder.\n
  LONGDESC
  def up
    init

    # ensure requirements
    unless @project[:id]
      warn("Git repository for #{gitpath} not found, have-you already import this project ?")
      exit
    end

    # prepare post request
    launch_req = { vm: { project_id: @project[:id], vmsize_id: @project[:vmsizes][0],
                         user_id: @user[:id], systemimage_id: @project[:systemimages][0],
                         technos: @project[:technos], is_auth: true, is_prod: false, is_cached: false,
                         is_backup: false, is_ci: false, is_ht: @project[:is_ht], layout: @user[:layout],
                         htlogin: @project[:login], htpassword: @project[:password], commit_id: commitid } }

    response = @conn.post do |req|
      req.url "/api/v1/vms/short"
      req.headers = rest_headers
      req.body = launch_req.to_json
    end

    json(response.body)[:vm]
  end

  # Display logs for a vm
  #
  desc "logs [idvm]", "Display some logs for a vm"
  long_desc <<-LONGDESC
    `ndeploy logs [idvm]`  Display some logs for a vm identified by [idvm] (view ndeploy list). And if [idvm] is missing, this command displays logs for last vm\n
  LONGDESC
  def logs(idvm=nil)
    logs = []
    init

    if idvm
      vmtologs = @vms.select { |vm| vm[:status] > 1 && vm[:id].to_i == idvm.to_i }[0]
    else
      vmtologs = @vm && @vm[:status] && @vm[:status] > 1 ? @vm : @vms.select { |vm| vm[:status] > 1 && vm[:user] == @user[:id] }.sort_by {|v| v[:id]}.reverse.first
    end

    # ensure requirement
    error("No vm running") unless vmtologs

    response = @conn.post do |req|
      req.url "/api/v1/vms/#{vmtologs[:id]}/logs"
      req.headers = rest_headers
    end

    logs.push response.body

    vmtologs[:uris].each do |uri|
      response = @conn.post do |req|
        req.url "/api/v1/uris/#{uri}/logs"
        req.headers = rest_headers
      end

      logs.push response.body
    end

    puts logs.join("\n")
  end

  # Display details for a vm
  #
  desc "details [idvm]", "Display some details for a vm"
  long_desc <<-LONGDESC
    `ndeploy details [idvm]`  Display some details for a vm identified by [idvm] (view ndeploy list). And if [idvm] is missing, this command displays details for last vm\n
  LONGDESC
  def details(idvm=nil)
    init

    if idvm
      vmtodetails = @vms.select { |vm| vm[:status] > 1 && vm[:id].to_i == idvm.to_i }[0]
    else
      vmtodetails = @vm && @vm[:status] && @vm[:status] > 1 ? @vm : @vms.select { |vm| vm[:status] > 1 && vm[:user] == @user[:id] }.sort_by {|v| v[:id]}.reverse.first
    end

    # ensure requirement
    error("No vm running") unless vmtodetails

    project = @conn.get do |req|
      req.url "/api/v1/projects/#{vmtodetails[:project]}"
      req.headers = rest_headers
    end

    user = @conn.get do |req|
      req.url "/api/v1/users/#{vmtodetails[:user]}"
      req.headers = rest_headers
    end

    puts "Name: #{vmtodetails[:name]}"
    puts "User: #{json(user.body)[:user][:email]}"
    puts "Project: #{json(project.body)[:project][:name]}"
    puts "Branch: #{vmtodetails[:commit].sub(/^[0-9]+-/,'').sub(/-[0-9a-zA-Z]+$/, '')}"
    puts "Commit: #{vmtodetails[:commit].sub(/^.+-/,'')}"
    puts "Remote: ssh modem@#{vmtodetails[:floating_ip]}"
    puts "Samba Share: smb://modem:#{vmtodetails[:termpassword]}@#{vmtodetails[:floating_ip]}/#{vmtodetails[:name].gsub(/\..*$/,'')}"
    puts "Technos"
    vmtodetails[:technos].each do |techno_id|
      resptechno = @conn.get do |req|
        req.url "/api/v1/technos/#{techno_id}"
        req.headers = rest_headers
      end

      techno = json(resptechno.body)[:techno]

      resptype = @conn.get do |req|
        req.url "/api/v1/technotypes/#{techno[:technotype]}"
        req.headers = rest_headers
      end
      technotype = json(resptype.body)[:technotype][:name]

      puts "  #{technotype} => #{techno[:name]}"
    end
    puts "Prod: #{vmtodetails[:is_prod]}"
    puts "BasicAuth: #{vmtodetails[:is_auth]}"
    puts "Htaccess: #{vmtodetails[:is_ht]}"
    puts "Varnish Cache: #{vmtodetails[:is_cached]}"
    puts "Backup: #{vmtodetails[:is_backup]}"
    puts "Uris"
    vmtodetails[:uris].each do |uri_id|
      respuri = @conn.get do |req|
        req.url "/api/v1/uris/#{uri_id}"
        req.headers = rest_headers
      end

      uri = json(respuri.body)[:uri]

      respframework = @conn.get do |req|
        req.url "/api/v1/frameworks/#{uri[:framework]}"
        req.headers = rest_headers
      end
      framework = json(respframework.body)[:framework][:name]

      puts "  #{uri[:absolute]}"
      puts "    HtLogin: #{vmtodetails[:htlogin]}" if vmtodetails[:is_auth]
      puts "    HtPassword: #{vmtodetails[:htpassword]}" if vmtodetails[:is_auth]
      puts "    Framework: #{framework}"
      puts "    Path: #{uri[:path]}"
      puts "    Aliases: #{uri[:aliases]}" if uri[:aliases] && !uri[:aliases].empty?
      puts "    Env vars: #{uri[:envvars]}" if uri[:envvars] && !uri[:envvars].empty?
      puts "    Ip filter: #{uri[:ipfilter]}" if uri[:ipfilter] && !uri[:ipfilter].empty?
    end
  end

  # Share project folder from vm to local computer
  #
  desc "folder [idvm] [workspace]", "Share project folder from a vm"
  long_desc <<-LONGDESC
    `ndeploy folder [idvm] [workspace]`  Share project folder from vm identified by [idvm] (see ndeploy list), to local folder. The parent of this last one is current directory by default or [workspace]\n
  LONGDESC
  def folder(idvm=nil, workspace=nil)
    init

    if idvm
      vmtoshare = @vms.select { |vm| vm[:status] > 1 && vm[:id].to_i == idvm.to_i }[0]
    else
      vmtoshare = @vms.select { |vm| vm[:status] > 1 && vm[:user] == @user[:id] }.sort_by {|v| v[:id]}.reverse.first
    end

    # ensure requirements
    if workspace.nil? && File.exists?('.git')
      warn("Please execute folder command outside a git repository")
      exit
    end

    unless vmtoshare
      warn("A valid vmId is needed. Please execute \"ndeploy list\", get a vmId (firstcolumn) and execute again \"ndeploy share [vmId]\"")
      exit
    end

    vmname = vmtoshare[:name].sub(/\..*$/,'')
    workspace = "#{workspace}/" if workspace && !workspace.match(/.*\/$/)
    foldermount = "#{workspace}#{vmname}"
    success = false

    if system "mkdir -p #{foldermount}"
      # test if mac os x
      if File.exists?('/usr/bin/sw_vers')
        system "umount -f #{foldermount} >/dev/null 2>&1"
        success = system "mount -t smbfs smb://modem:#{vmtoshare[:termpassword]}@#{vmtoshare[:floating_ip]}/#{vmname} #{foldermount}"
      else
        system "sudo umount -f #{foldermount} >/dev/null 2>&1"
        success = system "sudo mount -t cifs -o username=modem,password=#{vmtoshare[:termpassword]} //#{vmtoshare[:floating_ip]}/#{vmname} #{foldermount}"
      end

      if success
        warn("Project Folder is mounted with success in #{foldermount}")
      else
        warn("An error occurs during remote folder mount. Please ensure that your vpn connection is up and running.")
      end
    else
      warn("An error occurs during remote folder mount, please ensure that current user has permission rights to mount into #{foldermount}.")
    end
  end

  # alias "share" (old name) for folder command
  map share: :folder

  # Launch a setted commit into a new vm on nextdeploy cloud
  #
  desc "launch [name] [branch]", "Launch a new vm"
  long_desc <<-LONGDESC
    `ndeploy launch [name] [branch]`  launch [branch] (default is master) for project [name] into a new vm\n
  LONGDESC
  def launch(name=nil, branch='master')
    init

    # ensure requirements
    error("Argument name is missing") unless name
    error("No projects for #{@user[:email]}") if @projects.empty?

    # select project following parameter
    proj = @projects.select { |p| p[:name] == name }
    # return if parameter is invalid
    error("Project #{name} not found") if !proj || proj.empty?
    @project = proj[0]

    # get branch from api server
    get_branche(branch)
    error("Branch #{branch} not found") if !@branche

    # prepare post request
    launch_req = { vm: { project_id: @project[:id], vmsize_id: @project[:vmsizes][0], user_id: @user[:id], technos: @project[:technos], systemimage_id: @project[:systemimages][0], is_auth: true, is_prod: false, is_cached: false, is_backup: false, is_ci: false, is_ht: @project[:is_ht], layout: @user[:layout], htlogin: @project[:login], htpassword: @project[:password], commit_id: "#{@branche[:commits][0]}" } }

    response = @conn.post do |req|
      req.url "/api/v1/vms/short"
      req.headers = rest_headers
      req.body = launch_req.to_json
    end

    json(response.body)[:vm]
  end

  # Destroy a vm
  #
  desc "destroy [idvm]", "destroy a vm"
  long_desc <<-LONGDESC
    `ndeploy destroy [idvm]`  destroy a vm identified by [idvm] (see ndeploy list)\n
  LONGDESC
  def destroy(idvm=nil)
    init

    vmtodestroy = @vm
    if idvm
      vmtodestroy = @vms.select { |vm| vm[:id].to_i == idvm.to_i && vm[:user] == @user[:id] }[0]
    end

    # ensure requirements
    unless vmtodestroy && vmtodestroy.any?
      warn("No vm to destroy")
      exit
    end

    response = @conn.delete do |req|
      req.url "/api/v1/vms/#{vmtodestroy[:id]}"
      req.headers = rest_headers
    end
  end

  # Reboot a vm
  #
  desc "reboot [--type=HARD] [idvm]", "Reboot a vm"
  long_desc <<-LONGDESC
    `ndeploy reboot [--type=HARD] [idvm]`\n
    reboot a vm identified by [idvm] (see ndeploy list)\n
    software reboot by default, hardware reboot if --type=HARD option\n
  LONGDESC
  option :type
  def reboot(idvm=nil)
    init

    type = (options[:type] && options[:type] != 'SOFT')  ? 'HARD' : 'SOFT'
    vmtoreboot = @vm
    if idvm
      vmtoreboot = @vms.select { |vm| vm[:id].to_i == idvm.to_i && vm[:user] == @user[:id] }[0]
    end

    # ensure requirements
    unless vmtoreboot && vmtoreboot.any?
      warn("No vm to reboot")
      exit
    end

    # prepare post request
    reboot_req = { reboot: {type: type} }

    response = @conn.post do |req|
      req.url "/api/v1/vms/#{vmtoreboot[:id]}/reboot"
      req.headers = rest_headers
      req.body = reboot_req.to_json
    end
  end

  # List current active vms
  #
  desc "list [--all] [--head n]", "list launched vms for current user."
  long_desc <<-LONGDESC
    `ndeploy list`  list launched vms for current user\n
    `ndeploy list --all`  list launched vms for all users in our scope (relevant only for "project lead" or "admin" users)\n
    `ndeploy list --head n`  display only the 'n' last vms\n
  LONGDESC
  option :all
  option :head
  def list
    init

    # ensure requirements
    error("No vms for #{@user[:email]}") if @vms.empty?

    nblines = 0
    @vms.sort_by {|v| v[:id]}.reverse.each do |vm|
      project = @projects.select { |project| project[:id] == vm[:project] }
      status = "RUNNING"
      # put url if vm is running
      url = ", #{vm[:name]}"
      url = "" if vm[:status] <= 1
      # update status field
      status = "SETUP" if vm[:status] < 0
      status = "ERROR" if vm[:status] == 1
      # print only his own vms
      if vm[:user] == @user[:id] || options[:all]
        if !options[:head] || nblines < options[:head].to_i
          puts "#{vm[:id]}, #{project[0][:name]}, #{vm[:commit].gsub(/^[0-9]+-/, '')[0,16]}, #{status}#{url}"
          nblines += 1
        end
      end
    end
  end

  # List current active vms
  #
  desc "supervise", "Check vms health"
  long_desc <<-LONGDESC
    `ndeploy supervise`  Check vms health\n
  LONGDESC
  def supervise
    # check ansible installation
    unless File.exists?('/usr/bin/ansible') || File.exists?('/usr/local/bin/ansible')
        error('No ansible binary in the system')
    end

    init

    # ensure requirements
    error("No vms for #{@user[:email]}") if @vms.empty?

    # prepare temporary folder for ansible execution
    Dir.mkdir('/tmp/playbook') unless Dir.exists?('/tmp/playbook')
    Dir.chdir('/tmp/playbook')

    begin
      open('ansible.cfg', 'w') do |f|
        f << "[defaults]\n"
        f << "hostfile = inventory\n"
        f << "host_key_checking = False\n"
      end
    rescue
      error("Create supervise file failed")
    end

    technos = @vms.map{|vm| vm[:technos]}.flatten(1).uniq
    technos.each do |techno_id|
      inventory(techno_id)

      resptechno = @conn.get do |req|
        req.url "/api/v1/technos/#{techno_id}"
        req.headers = rest_headers
      end

      playbook = json(resptechno.body)[:techno][:playbook]
      next if playbook.empty?

      begin
        open('playbook.yml', 'w') do |f|
          f << playbook
        end
      rescue
        error("Create playbook file failed")
      end

      probes = %x{ansible-playbook playbook.yml | grep ndeploy | sed 's;^.*ndeploy:;;' | sed 's;";;'}.split(/\n+/)
      probes.each do |probe|
        vm_id = probe.split(':')[0]
        status = probe.split(':')[1].to_i

        @conn.post do |req|
          req.url "/api/v1/supervises/#{vm_id}/status"
          req.headers = rest_headers
          req.body = { techno_id: techno_id, status: status }.to_json
        end
      end
    end
  end

  # List projects for current user
  #
  desc "projects", "list projects for current user"
  def projects
    init

    # ensure requirements
    error("No projects for #{@user[:email]}") if @projects.empty?

    @projects.sort_by! { |project| project[:name] }
    @projects.each { |project| puts "#{project[:name]}" }
  end

  # Clone a project by his name
  #
  desc "clone [name]", "clone project in current folder"
  def clone(name=nil)
    init

    # ensure requirements
    error("Argument name is missing") unless name
    error("No projects for #{@user[:email]}") if @projects.empty?

    # select project following parameter
    proj = @projects.select { |p| p[:name] == name }
    # return if parameter is invalid
    error("Project #{name} not found") if !proj || proj.empty?
    # else clone the project
    @project = proj[0]
    exec "git clone git@#{@project[:gitpath]}"
  end

  # Display sshkeys associated to current user into NextDeploy
  #
  desc "sshkeys", "List sshkeys actually associated to the current user"
  def sshkeys
    init

    @ssh_keys.each { |sshkey| puts sshkey[:key] }
  end

  # Puts a ssh key for the current user into NextDeploy
  #
  desc "sshkey", "Put your public ssh key (id_rsa.pub) onto NextDeploy"
  def sshkey
    init

    unless File.exists?("#{Dir.home}/.ssh/id_rsa.pub")
      error("No id_rsa.pub for current user")
    end

    key = open("#{Dir.home}/.ssh/id_rsa.pub").read.tr("\n", '')
    keyname = "sshkey-#{Socket.gethostname}"

    # check if this key is already associated to this user
    @ssh_keys.each do |sshkey|
      # normalize the two keys string and compre them.
      # HACK: ugly line :(
      if key.gsub(/^ssh-rsa /, '').gsub(/ .*$/, '').eql? sshkey[:key].gsub(/^ssh-rsa /, '').gsub(/ .*$/, '')
        error("Your current ssh key is already associated to your user")
      end
    end

    # prepare post request
    sshkey_req = { sshkey: { user_id: @user[:id], key: key, name: keyname } }

    response = @conn.post do |req|
      req.url "/api/v1/sshkeys"
      req.headers = rest_headers
      req.body = sshkey_req.to_json
    end

    sshkeys
  end

  # Ssh into remote vm
  #
  desc "ssh [idvm]", "ssh into a vm"
  long_desc <<-LONGDESC
    `ndeploy ssh [idvm]`  ssh into a vm identified by [idvm] (view ndeploy list). If [idvm] is missing, the last vm is the default one\n
  LONGDESC
  def ssh(idvm=nil)
    init

    if idvm
      vmtossh = @vms.select { |vm| vm[:id].to_i == idvm.to_i }[0]
    else
      vmtossh = @vm ? @vm : @vms.select { |vm| vm[:user] == @user[:id] }.sort_by {|v| v[:id]}.reverse.first
    end

    # ensure requirement
    error("No vm to ssh") unless vmtossh && vmtossh.any?

    exec "ssh modem@#{vmtossh[:floating_ip]}"
  end

  # Upload an asset archive or a sql/mongo dump onto ftp repository dedicated to project
  #
  desc "putftp assets|dump [project] [file]", "Put a file onto project ftp"
  long_desc <<-LONGDESC
    `ndeploy putftp assets|dump [--branch b] [--pathuri p] [project] [file]`  put an assets archive [file] or a dump [file] for the [project]. The option [pathuri] specifies the endpoint (a project can have multiple endpoints). The option [branch] specifies the branch targetting the file (we can have assets or dump for each branch). If these 2 last options are indicated, the filename is automatically well renamed.\n
  LONGDESC
  option :branch
  option :pathuri
  def putftp(typefile=nil, name=nil, file=nil)
    init

    # ensure requirement
    error("You must provide type of file to push: assets or dump") unless typefile
    error("You must provide type of file to push: assets or dump") if typefile == 'backup'
    error("Argument name is missing") unless name
    error("File to push is missing") unless file
    error("No projects for #{@user[:email]}") if @projects.empty?

    # rename file or let as it is
    isrename = (options[:branch] && options[:pathuri]) ? true : false
    # select project following parameter
    proj = @projects.select { |p| p[:name] == name }
    # return if parameter is invalid
    error("Project #{name} not found") if !proj || proj.empty?
    @project = proj[0]

    if typefile == 'assets'
      if isrename
        ftp_filename = "#{options[:branch]}_#{options[:pathuri]}_assets.tar.gz"
      else
        ftp_filename = file
      end
    else
      # mongo dump
      if isrename
        ftp_filename = "#{options[:branch]}_#{options[:pathuri]}_#{file}"
      else
        ftp_filename = file
      end
    end

    login_ftp = @project[:gitpath].gsub(/^.*\//, '')
    (@project[:password].empty?) ? (password_ftp = 'nextdeploy') : (password_ftp = @project[:password])

    # upload files
    ftp_file = File.new(file)
    error("File #{file} not found") unless File.exists?(file)
    Net::FTP.open(@ftpendpoint, login_ftp, password_ftp) do |ftp|
      ftp.putbinaryfile(ftp_file, "#{typefile}/#{ftp_filename}")
    end

  end

  # Download an asset archive or a sql/mongo dump from ftp repository dedicated to project
  #
  desc "getftp assets|dump|backup [project] [file]", "Get a file from project ftp"
  long_desc <<-LONGDESC
    `ndeploy getftp assets|dump|backup [project] [file]`  Get an assets archive, a database dump, or a backup for the [project].\n
  LONGDESC
  def getftp(typefile=nil, name=nil, file=nil)
    init

    # ensure requirement
    error("You must provide type of file to push: assets, backup or dump") unless typefile
    error("Argument name is missing") unless name
    error("No projects for #{@user[:email]}") if @projects.empty?

    # select project following parameter
    proj = @projects.select { |p| p[:name] == name }
    # return if parameter is invalid
    error("Project #{name} not found") if !proj || proj.empty?

    @project = proj[0]
    (typefile == 'assets') ? (ftp_filename = 'default_server_assets.tar.gz') : (ftp_filename = 'default_server.sql.gz')
    ftp_filename = file if file
    login_ftp = @project[:gitpath].gsub(/^.*\//, '')
    (@project[:password].empty?) ? (password_ftp = 'nextdeploy') : (password_ftp = @project[:password])

    Net::FTP.open(@ftpendpoint, login_ftp, password_ftp) do |ftp|
      ftp.chdir("#{typefile}")
      ftp.passive = true
      ftp.getbinaryfile("#{ftp_filename}", "#{ftp_filename}")
    end

  end

  # List asset archive or a sql/mongo dump from ftp repository dedicated to project
  #
  desc "listftp assets|dump|backup [project]", "List files from project ftp"
  long_desc <<-LONGDESC
    `ndeploy listftp assets|dump|backup [project]`  List assets archive, backup, or a database dump for the [project].\n
  LONGDESC
  def listftp(typefile=nil, name=nil, file=nil)
    init

    # ensure requirement
    error("You must provide type of file to push: assets or dump") unless typefile
    error("Argument name is missing") unless name
    error("No projects for #{@user[:email]}") if @projects.empty?

    # select project following parameter
    proj = @projects.select { |p| p[:name] == name }
    # return if parameter is invalid
    error("Project #{name} not found") if !proj || proj.empty?
    @project = proj[0]

    login_ftp = @project[:gitpath].gsub(/^.*\//, '')
    (@project[:password].empty?) ? (password_ftp = 'nextdeploy') : (password_ftp = @project[:password])

    # list files
    Net::FTP.open(@ftpendpoint, login_ftp, password_ftp) do |ftp|
      puts ftp.list("#{typefile}/")
    end

  end

  # Get / set config for nextdeploy
  #
  desc "config [endpoint] [username] [password]", "get/set properties settings for nextdeploy"
  def config(endp=nil, username=nil, pass=nil)
    # get actual settings with disable error log
    @nolog = true
    init_properties
    @nolog = nil

    @endpoint = endp if endp
    @email = username if username
    @password = pass if pass

    # write new setting file
    if endp || username || pass
      open("#{Dir.home}/.nextdeploy.conf", 'w') do |f|
        f << "email: #{@email}\n"
        f << "password: #{@password}\n"
        f << "endpoint: #{@endpoint}\n"
      end
    end

    # confirm this new settings
    init_properties

    puts "Username: #{@email}"
    puts "Password: #{@password}"
    puts "Endpoint: #{@endpoint}"
  end

  no_commands do

    # Init datas
    #
    def init
      init_constants
      init_properties
      init_conn
      token
      init_sshkeys
      init_vms
      init_projects
      init_brands
      init_frameworks
      get_project
      get_vm
    end

    # define some constants
    #
    def init_constants
      @@version = "1.9"
      @@remote_cli = "http://cli.nextdeploy.io"
      @@docker_ip = get_docker_ip
    end

    # Retrieve settings parameters
    #
    def init_properties
      fp = nil
      @email = nil
      @password = nil
      @endpoint = nil

      # Open setting file
      if File.exists?('nextdeploy.conf')
        fp = File.open('nextdeploy.conf', 'r')
      elsif File.exists?("#{Dir.home}/.nextdeploy.conf")
        fp = File.open("#{Dir.home}/.nextdeploy.conf", 'r')
      else
        if ! File.exists?('/etc/nextdeploy.conf')
          error('no nextdeploy.conf or /etc/nextdeploy.conf')
        end
        fp = File.open('/etc/nextdeploy.conf', 'r')
      end

      # Get properties
      while (line = fp.gets)
        if (line.match(/^email:.*$/))
          @email = line.gsub('email:', '').squish
        end

        if (line.match(/^password:.*$/))
          @password = line.gsub('password:', '').squish
        end

        if (line.match(/^endpoint:.*$/))
          @endpoint = line.gsub('endpoint:', '').squish
          @ftpendpoint = "f.#{@endpoint.gsub(/api\./,'')}"
        end
      end
      fp.close

      error("no email into nextdeploy.conf") if @email == nil
      error("no password into nextdeploy.conf") if @password == nil
      error("no endpoint into nextdeploy.conf") if @endpoint == nil
    end

    # get remote cli version
    #
    def get_remote_version
      open("#{@@remote_cli}/LATEST").read.gsub(/.*cli-/, '').gsub(/\.tar\.gz/,'').tr("\n", '')
    end

    # Get current git url
    #
    # No params
    # @return [String] the git path
    def gitpath
      %x{git config --get remote.origin.url | sed "s;^.*root/;;" | sed "s;\.git$;;"}.squish
    end

    # Get current commit
    #
    # No param
    # @return [String] a commit hash
    def currentcommit
      %x{git rev-parse HEAD}.squish
    end

    # Get current branch
    #
    # No params
    # @return [String] a branch name
    def currentbranch
      %x{git branch | grep "*" | sed "s;* ;;"}.squish
    end

    # Get unique id (for the model of nextdeploy) for current commit
    #
    # No params
    # @return [String] id of the commit
    def commitid
      "#{@project[:id]}-#{currentbranch}-#{currentcommit}"
    end

    # Get current project, technos and endpoints follow the gitpath value
    #
    # No params
    # @return [Array[String]] json output for a project
    def get_project
      gitp = gitpath

      # if we are not into git project, return
      return if gitp.empty?

      response = @conn.get do |req|
        req.url "/api/v1/projects/git/#{gitp}"
        req.headers = rest_headers
      end

      if response.body == "null"
        @project = {}
        @endpoints = []
        return
      end

      # Init project global variable
      @project = json(response.body)[:project]
      @projectname = @project[:name].gsub(/[\._-]/, '').gsub(/www/, '')

      # Init endpoints global array
      @endpoints = @project[:endpoints].map do |ep_id|
        respep = @conn.get do |req|
          req.url "/api/v1/endpoints/#{ep_id}"
          req.headers = rest_headers
        end

        ep = json(respep.body)[:endpoint]

        respframework = @conn.get do |req|
          req.url "/api/v1/frameworks/#{ep[:framework]}"
          req.headers = rest_headers
        end
        framework = json(respframework.body)[:framework]
        ep[:frameworkname] = framework[:name]
        ep[:dockercompose] = framework[:dockercompose]

        ep
      end

      # Init technos global array
      @technos = @project[:technos].map do |techno_id|
        resptechno = @conn.get do |req|
          req.url "/api/v1/technos/#{techno_id}"
          req.headers = rest_headers
        end

        techno = json(resptechno.body)[:techno]
      end
    end

    # Get branch object
    #
    # No params
    # @return [Array[String]] json output for a branch
    def get_branche(branch='master')

      response = @conn.get do |req|
        req.url "/api/v1/branches/#{@project[:id]}-#{branch}"
        req.headers = rest_headers
      end

      if response.body == "null"
        @branche = nil
        return
      end

      @branche = json(response.body)[:branche]
    end

    # get he vm for current commit
    #
    # No params
    # @return [Array[String]] json output for a vm
    def get_vm

      # if we are not into git project, return
      gitp = gitpath
      return if gitp.empty?

      commit = commitid

      response = @conn.get do |req|
        req.url "/api/v1/vms/user/#{@user[:id]}/#{URI::encode(commit)}"
        req.headers = rest_headers
      end

      if response.body == "null" || response.status != 200 || !json(response.body)[:vms]
        @vm = {}
        return
      end

      @vm = json(response.body)[:vms][0]
    end

    # Init rest connection
    #
    def init_conn
      @conn = Faraday.new(:url => "https://#{@endpoint}", ssl: {verify:false}) do |faraday|
        faraday.adapter  :net_http_persistent
      end
    end

    # Authenticate user
    #
    # @param [String] email of the user
    # @param [String] password of the user
    # No return
    def authuser(email, password)
      auth_req = { user: { email: email, password: password } }

      begin
        response = @conn.post do |req|
         req.url "/api/v1/users/sign_in"
         req.headers['Content-Type'] = 'application/json'
         req.headers['Accept'] = 'application/json'
         req.body = auth_req.to_json
        end
      rescue => e
        warn("Issue during authentification, bad email or password ?")
        warn(e)
        exit
      end

      json_auth = json(response.body)
      if ! json_auth[:success].nil? && json_auth[:success] == false
        warn(json_auth[:message])
        exit
      end

      @user = json_auth[:user]
    end

    # Get all projects properties
    #
    # No param
    # No return
    def init_projects
      @projects = []

      response = @conn.get do |req|
        req.url "/api/v1/projects"
        req.headers = rest_headers
      end

      @projects = json(response.body)[:projects]
    end

    # Get all vms properties
    #
    # No params
    # No return
    def init_vms
      @vms = []

      response = @conn.get do |req|
        req.url "/api/v1/vms"
        req.headers = rest_headers
      end

      @vms = json(response.body)[:vms]
    end

    # Get all sshkeys properties
    #
    # No return
    def init_sshkeys
      @ssh_keys = []
      @ssh_key = { name: 'nosshkey' }

      response = @conn.get do |req|
        req.url "/api/v1/sshkeys"
        req.headers = rest_headers
      end

      @ssh_keys = json(response.body)[:sshkeys]
      @ssh_key = @ssh_keys.first if @ssh_keys.length
    end

    # Get all brands properties
    #
    # No return
    def init_brands
      response = @conn.get do |req|
        req.url "/api/v1/brands"
        req.headers = rest_headers
      end

      @brands = json(response.body)[:brands]
    end

    # Get all frameworks properties
    #
    # No return
    def init_frameworks
      response = @conn.get do |req|
        req.url "/api/v1/frameworks"
        req.headers = rest_headers
      end

      @frameworks = json(response.body)[:frameworks]
    end

    # Get all systemimages properties
    #
    # No return
    def init_systems
      response = @conn.get do |req|
        req.url "/api/v1/systemimages"
        req.headers = rest_headers
      end

      @systems = json(response.body)[:systemimages]
    end

    # generate inventory file for ansible supervise
    #
    def inventory(techno_id=0)
      init

      # ensure requirements
      error("No vms for #{@user[:email]}") if @vms.empty?

      begin
        open('inventory', 'w') do |f|
          @vms.sort_by {|v| v[:id]}.reverse.each do |vm|
            matchgroup = 0

            vm[:technos].each do |t|
              matchgroup = 1 if techno_id == t
            end
            next if matchgroup == 0

            # if os is xenial, => python2.7
            python = '/usr/bin/python'
            f << "#{vm[:id]} ansible_ssh_host=#{vm[:floating_ip]} ansible_ssh_user=modem ansible_ssh_private_key_file=~/.ssh/id_rsa ansible_python_interpreter=#{python}\n"
          end
        end
      rescue
        error("Create inventory file failed")
      end
    end

    # Stop (and destory if paremeter is true) docker-compose containers
    #
    # @params [Boolean] isdestroy
    def docker_compose_stop(isdestroy)
      rootFolder = Dir.pwd
      # clean old containers
      if File.exists?("#{rootFolder}/tmp/docker/docker#{@projectname}.yml")
        # go to dockercompose folder
        Dir.chdir("#{rootFolder}/tmp/docker")
        # kill containers
        system "docker-compose -p #{@projectname} -f docker#{@projectname}.yml stop"
        # flush completely containers only for reinstall option
        system "docker-compose -p #{@projectname} -f docker#{@projectname}.yml rm -f -v --all" if isdestroy
        system "rm -f docker#{@projectname}.yml" if isdestroy
        Dir.chdir(rootFolder)
      end

      system 'rm -rf tmp' if isdestroy
    end

    # Start docker-compose containers
    #
    def docker_compose_up
      rootFolder = Dir.pwd
      # if docker compose file already exists, just start containers
      if File.exists?("#{rootFolder}/tmp/docker/docker#{@projectname}.yml")
        # go to dockercompose folder
        Dir.chdir("#{rootFolder}/tmp/docker")
        # Start containers
        system "docker-compose -p #{@projectname} -f docker#{@projectname}.yml up -d"
        Dir.chdir(rootFolder)
      end
    end

    # Install docker-compose containers
    #
    def docker_compose_gen
      rootFolder = Dir.pwd
      isimport = true
      composerLines = []
      containerPorts = {}

      # if docker compose file already exists, return
      if File.exists?("#{rootFolder}/tmp/docker/docker#{@projectname}.yml")
        warn("tmp/docker/docker#{@projectname}.yml already exists, no need to generate")
        return
      end

      local_ip = @@docker_ip
      port = 9181
      until port_open?(local_ip, port) do
        port = port + 1
      end

      @endpoints.each do |ep|
        containername = "ep_#{ep[:path]}_#{@projectname}"
        envvars = ep[:envvars].split(' ').map { |ev| "    #{ev.sub('=',': ')}" }.join("\n")
        dockercompose = ep[:dockercompose]
        next if dockercompose.empty?
        containerPorts["#{containername}"] = port
        # replace container name, docroot, envvars and ports
        dockercompose.gsub!('%%CONTAINERNAME%%', "#{containername}")
        dockercompose.gsub!('%%DOCROOT%%', "#{Dir.pwd}/#{ep[:path]}")
        dockercompose.gsub!('%%PORT%%', "#{port}")
        dockercompose.gsub!('%%PORTEP%%', "#{ep[:port]}")
        envvars = "  environment:\n#{envvars}" unless envvars.empty? || /environment:/.match(dockercompose)
        dockercompose.gsub!('%%ENVVARS%%', envvars)
        dockercompose.gsub!(/^$\n/, '')
        dockercompose.gsub!('%%PROJECTNAME%%', @projectname)
        dockercompose.gsub!('%%EPPATH%%', ep[:path])
        # push into composerLines and containerList arrays
        composerLines << dockercompose

        port = port + 1
        until port_open?(@@docker_ip, port) do
          port = port + 1
        end
      end

      # replace endpoints host into composer template
      @endpoints.each do |ep|
        containername = "ep_#{ep[:path]}_#{@projectname}"
        port = containerPorts["#{containername}"]
        eppath = ep[:path].upcase
        composerLines.map! { |cl| cl.gsub("%{URI_#{eppath}}", "#{local_ip}").gsub("%{PORT_#{eppath}}", "#{port}") }
      end

      # Ensure tmp is in gitignore
      system 'grep -e ^/tmp$ .gitignore >/dev/null 2>&1 || echo -e "\n/tmp" >> .gitignore'
      # Prepare folder for docker work
      Dir.mkdir("#{rootFolder}/tmp") unless Dir.exists?("#{rootFolder}/tmp")

      # get technos and frameworks
      @technos.each do |techno|
        dockercompose = techno[:dockercompose]
        next if dockercompose.nil? || dockercompose.empty?
        technoname = techno[:name].sub(/-.*$/,'').downcase
        # dont import if datas already exists
        if Dir.exists?("#{rootFolder}/tmp/#{technoname}")
          isimport = false
        elsif docker_native?
          Dir.mkdir("#{rootFolder}/tmp/#{technoname}")
          File.chmod(0777, "#{rootFolder}/tmp/#{technoname}")
        else
          # if no native docker, disable persistent storage
          dockercompose.gsub!(/^.*volumes:.*$\n/,'')
          dockercompose.gsub!(/^.*%%TECHNOFOLDER%%.*$\n/,'')
        end
        containername = "#{technoname}_#{@projectname}"
        dockercompose.gsub!('%%CONTAINERNAME%%', "#{containername}")
        dockercompose.gsub!('%%TECHNOFOLDER%%', "#{rootFolder}/tmp/#{technoname}")
        dockercompose.gsub!('%%PROJECTNAME%%', @projectname)
        composerLines << dockercompose
      end

      begin
        Dir.mkdir("#{rootFolder}/tmp/docker") unless Dir.exists?("#{rootFolder}/tmp/docker")
        open("#{rootFolder}/tmp/docker/docker#{@projectname}.yml", File::RDWR|File::CREAT) do |f|
          f.flock(File::LOCK_EX)
          f.rewind
          f.puts "version: '2'"
          f.puts "services:"
          f.puts composerLines.join("\n").gsub(/^/, '  ')
          f.flush
          f.truncate(f.pos)
        end
      rescue => me
        warn("Create docker-composer file for #{@projectname} failed, #{me.message}")
        exit
      end

      # Ensure we are back to root
      Dir.chdir(rootFolder)

      # preinstall stuffs
      docker_preinstall
      docker_npmsh(true)

      # get last containers, ... yes, it's ugly !
      Dir.chdir("#{rootFolder}/tmp/docker")
      system "grep 'image: ' docker#{@projectname}.yml | sed 's;.* ;;' | while read DIMG; do docker pull $DIMG;done"

      # Back to root
      Dir.chdir(rootFolder)
      docker_compose_up

      docker_waiting_containers
      # postinstall stuffs
      docker_create_databases
      docker_composersh(true)
      docker_import(isimport)
      docker_postinstall

      # execute postinstall nextdeploy task
      if isimport
        Dir.chdir(rootFolder)
        docker_postinstall_script
      end

      docker_updb
      docker_cc
    end

    def docker_create_databases
      containername = "mysql_#{@projectname}"
      @endpoints.each do |ep|
        # ensure database is well created at this step, .... ugly !!!
        system "docker exec -t mysql_#{@projectname} /usr/bin/mysql -u root -p8to9or1 -e 'create database #{ep[:path]} character set=utf8 collate=utf8_unicode_ci' >/dev/null 2>&1"
      end
    end

    def docker_list_endpoints
      # give endpoints output on terminal
      @endpoints.each do |ep|
        containername = "ep_#{ep[:path]}_#{@projectname}"
        port = docker_getport(containername)
        puts "Your #{ep[:path]} endpoint is reached on http://#{@@docker_ip}:#{port}/"
      end
    end

    # Ssh to conainer
    #
    def docker_ssh
      index = 0
      choice = '0'
      choices = []
      sentence = ""

      index = 0
      @endpoints.each do |ep|
        framework = ep[:frameworkname]
        containername = "ep_#{ep[:path]}_#{@projectname}"
        sentence << "[#{index}] - #{containername} \n"
        choices << "#{index}"
        index = index + 1
      end

      # if only one endpoint, ssh into in without prompt
      choice = ask("Which endpoint ?\n#{sentence}", limited_to: choices) unless index == 1

      index = 0
      @endpoints.each do |ep|
        if choice.to_i == index
          framework = ep[:frameworkname]
          containername = "ep_#{ep[:path]}_#{@projectname}"
          exec "docker exec -i -t #{containername} /bin/bash"
        end
        index = index + 1
      end
    end

    # Ssh to conainer
    #
    def docker_console
      index = 0
      choice = '0'
      choices = []
      sentence = ""
      rootFolder = Dir.pwd

      index = 0
      @endpoints.each do |ep|
        framework = ep[:frameworkname]
        containername = "ep_#{ep[:path]}_#{@projectname}"
        sentence << "[#{index}] - #{containername} \n"
        choices << "#{index}"
        index = index + 1
      end

      # if only one endpoint, ssh into in without prompt
      choice = ask("Which endpoint ?\n#{sentence}", limited_to: choices) unless index == 1

      index = 0
      @endpoints.each do |ep|
        if choice.to_i == index
          Dir.chdir("#{rootFolder}/#{ep[:path]}")
          framework = ep[:frameworkname]
          containername = "ep_#{ep[:path]}_#{@projectname}"
          cmd = ask("Which console command (#{framework}) ?\nno need to specify binary, only parameters\n")
          cmd.gsub!('/usr/bin/', '')
          cmd.gsub!('/usr/local/bin/', '')
          cmd.gsub!('/bin/', '')
          cmd.gsub!(/php ?/, '')
          # execute framework specific updb
          case framework
          when /Symfony/
            cmd.gsub!('bin/console', '')
            cmd.gsub!('app/console', '')
            system "docker pull nextdeploy/#{framework.downcase}console"
            system "docker run --net=#{@projectname}_default -v=#{Dir.pwd}:/var/www/html nextdeploy/#{framework.downcase}console #{cmd}"
          when /Drupal/
            cmd.gsub!('drush', '')
            system "docker pull nextdeploy/drush"
            system "docker run --net=#{@projectname}_default  -v=#{Dir.pwd}:/app nextdeploy/drush -y #{cmd} 2>/dev/null"
          when /Wordpress/
            cmd.gsub!('wp.phar', '')
            cmd.gsub!('wp', '')
            system "docker pull nextdeploy/wp"
            system "docker run --net=#{@projectname}_default  -v=#{Dir.pwd}:/app nextdeploy/wp #{cmd}"
          end

          docker_reset_permissions(containername)
        end
        index = index + 1
      end

      Dir.chdir("#{rootFolder}")
    end

    # Update project containers
    #
    def docker_update
      system 'git pull --rebase'
      docker_composersh
      docker_npmsh
      docker_updb
      docker_compose_stop(false)
      docker_compose_up
    end

    # Rebuild modules, launche updb and clear caches
    #
    def docker_rebuild
      docker_composersh(true)
      docker_npmsh(true)
      docker_updb
      docker_compose_stop(false)
      docker_compose_up
    end

    # Launch updb (update data models) for the project
    #
    def docker_updb
      rootFolder = Dir.pwd

      # execute updb cmds for each endpoints
      @endpoints.each do |ep|
        framework = ep[:frameworkname]
        containername = "ep_#{ep[:path]}_#{@projectname}"
        Dir.chdir("#{rootFolder}/#{ep[:path]}")

        # execute framework specific updb
        case framework
        when /Symfony/
          system "docker pull nextdeploy/#{framework.downcase}console"
          system "docker run --net=#{@projectname}_default -v=#{Dir.pwd}:/var/www/html nextdeploy/#{framework.downcase}console doctrine:schema:update --force"
        when /Drupal/
          system "docker pull nextdeploy/drush"
          system "docker run --net=#{@projectname}_default  -v=#{Dir.pwd}:/app nextdeploy/drush -y updb"
        end
      end
      Dir.chdir(rootFolder)

      docker_cc
    end

    # Clear application caches
    #
    def docker_cc
      rootFolder = Dir.pwd

      # execute updb cmds for each endpoints
      @endpoints.each do |ep|
        framework = ep[:frameworkname]
        containername = "ep_#{ep[:path]}_#{@projectname}"
        Dir.chdir("#{rootFolder}/#{ep[:path]}")

        # execute framework specific updb
        case framework
        when /Symfony/
          system "docker pull nextdeploy/#{framework.downcase}console"
          system "docker run --net=#{@projectname}_default -v=#{Dir.pwd}:/var/www/html nextdeploy/#{framework.downcase}console cache:clear --env=prod 2>/dev/null"
          system "docker run --net=#{@projectname}_default -v=#{Dir.pwd}:/var/www/html nextdeploy/#{framework.downcase}console cache:clear --env=dev 2>/dev/null"
          system "docker run --net=#{@projectname}_default -v=#{Dir.pwd}:/var/www/html nextdeploy/#{framework.downcase}console assets:install --symlink"
          system "docker run --net=#{@projectname}_default -v=#{Dir.pwd}:/var/www/html nextdeploy/#{framework.downcase}console assetic:dump >/dev/null 2>/dev/null"
        when /Drupal/
          system "docker pull nextdeploy/drush"
          system "docker run --net=#{@projectname}_default  -v=#{Dir.pwd}:/app nextdeploy/drush -y cc --all 2>/dev/null"
          system "docker run --net=#{@projectname}_default  -v=#{Dir.pwd}:/app nextdeploy/drush -y cr 2>/dev/null"
        when /Wordpress/
          system "docker pull nextdeploy/wp"
          system "docker run --net=#{@projectname}_default  -v=#{Dir.pwd}:/app nextdeploy/wp cache flush"
        end

        docker_reset_permissions(containername)
      end

      Dir.chdir(rootFolder)
    end

    # Launch composer install recursive script
    #
    def docker_composersh(reset=false)
      rootFolder = Dir.pwd

      # get last container version
      system "docker pull nextdeploy/composersh"

      @endpoints.each do |ep|
        containername = "ep_#{ep[:path]}_#{@projectname}"
        Dir.chdir("#{rootFolder}/#{ep[:path]}")
        system "docker run --net=#{@projectname}_default -v=#{Dir.pwd}:/app -w /app nextdeploy/composersh --reset #{reset}"

        docker_reset_permissions(containername)
      end

      Dir.chdir(rootFolder)
    end

    # Launch javascripts modules install
    #
    def docker_npmsh(reset=false)
      rootFolder = Dir.pwd

      # get last container version
      system "docker pull nextdeploy/npmsh"

      @endpoints.each do |ep|
        containername = "ep_#{ep[:path]}_#{@projectname}"
        Dir.chdir("#{rootFolder}/#{ep[:path]}")
        system "docker run -v #{Dir.pwd}:/app -w /app nextdeploy/npmsh --reset #{reset}"

        docker_reset_permissions(containername)
      end

      Dir.chdir(rootFolder)

      # npmsh used lot of resources, sleep 5s to let the system breaths
      sleep 5
    end

    # Execute NextDeploy datas import step
    #
    def docker_import(isimport=true)
      ismysql = '0'
      ismongo = '0'
      rootFolder = Dir.pwd

      # get last container version
      system "docker pull nextdeploy/import"

      # get technos
      @technos.each do |techno|
        technoname = techno[:name].sub(/-.*$/,'').downcase
        ismysql = '1' if /mysql/.match(technoname)
        ismongo = '1' if /mongo/.match(technoname)
      end

      @endpoints.each do |ep|
        framework = ep[:frameworkname]
        containername = "ep_#{ep[:path]}_#{@projectname}"
        login_ftp = @project[:gitpath].gsub(/^.*\//, '')
        password_ftp = @project[:password]
        port = docker_getport(containername)
        branchname = %x{git rev-parse --abbrev-ref HEAD | tr -d "\n"}

        # if drupal, execute site-install before import
        if framework.match(/Drupal/)
          profile = ''
          if Dir.exists?("#{ep[:path]}/profiles")
            Dir.chdir("#{ep[:path]}/profiles")
            profile = %x{find . -maxdepth 1 -type d -regex '^.*nextdeploy_.*$' | sed "s;./;;" | tr -d "\n"}
            Dir.chdir(rootFolder)
          end
          profile = 'standard' if profile.empty?

          # ensure settings are writable
          system "chmod +w #{ep[:path]}/sites/default"
          system "test -e #{ep[:path]}/sites/default/settings.php && chmod +w #{ep[:path]}/sites/default/settings.php"

          system "docker pull nextdeploy/drush"
          email = @user[:email]
          system "docker run --net=#{@projectname}_default  -v=#{Dir.pwd}/#{ep[:path]}:/app nextdeploy/drush -y site-install --locale=en --db-url=mysqli://root:8to9or1@mysql_#{@projectname}:3306/#{ep[:path]} --account-pass=admin --site-name=#{@projectname} --account-mail=#{email} --site-mail=#{email} #{profile}"
        end

        if isimport
          system "docker run --net=#{@projectname}_default -v=#{Dir.pwd}:/app nextdeploy/import  --branch #{branchname} --uri #{@@docker_ip}:#{port} --path #{ep[:path]} --framework #{framework.downcase} --ftpuser #{login_ftp} --ftppasswd #{password_ftp} --ftphost #{@ftpendpoint} --ismysql #{ismysql} --ismongo #{ismongo} --projectname #{@projectname}"
          docker_reset_permissions(containername)
        end
      end
    end

    # Execute NextDeploy datas export step
    #
    def docker_export
      rootFolder = Dir.pwd
      ismysql = '0'
      ismongo = '0'

      # get last container version
      system "docker pull nextdeploy/export"

      # get technos
      @technos.each do |techno|
        technoname = techno[:name].sub(/-.*$/,'').downcase
        ismysql = '1' if /mysql/.match(technoname)
        ismongo = '1' if /mongo/.match(technoname)
      end

      @endpoints.each do |ep|
        framework = ep[:frameworkname]

        containername = "ep_#{ep[:path]}_#{@projectname}"
        port = docker_getport(containername)
        Dir.chdir("#{rootFolder}/#{ep[:path]}")

        login_ftp = @project[:gitpath].gsub(/^.*\//, '')
        password_ftp = @project[:password]
        system "docker run --net=#{@projectname}_default -v=#{rootFolder}:/app nextdeploy/export --uri #{@@docker_ip}:#{port} --path #{ep[:path]} --framework #{framework.downcase} --ftpuser #{login_ftp} --ftppasswd #{password_ftp} --ftphost #{@ftpendpoint} --ismysql #{ismysql} --ismongo #{ismongo} --projectname #{@projectname}"
      end

      Dir.chdir(rootFolder)
    end

    # Execute NextDeploy sql client
    #
    def docker_sql
      containername = "mysql_#{@projectname}"
      exec "docker exec -t -i #{containername} /usr/bin/mysql -u root -p8to9or1"
    end

    # Execute NextDeploy mongo client
    #
    def docker_mongo
      containername = "mongo_#{@projectname}"
      exec "docker exec -t -i #{containername} /usr/bin/mongo"
    end

    # Execute preinstall task
    #
    def docker_preinstall
      rootFolder = Dir.pwd

      # execute preinstall cmds
      @endpoints.each do |ep|
        framework = ep[:frameworkname]
        containername = "ep_#{ep[:path]}_#{@projectname}"
        system "mkdir -p #{rootFolder}/#{ep[:path]}"
        Dir.chdir("#{rootFolder}/#{ep[:path]}")

        case framework
        when /Symfony/
          docker_preinstall_sf2(ep[:path])
        when /Wordpress/
          docker_preinstall_wp
        end
      end

      Dir.chdir(rootFolder)
    end

    # Preinstall cmds for wordpress
    #
    def docker_preinstall_wp
      # move wp-content for avoid replace it
      system "mv wp-content git-wp-content" unless File.exists?("wp-includes/version.php")
    end

    # Preinstall cmds for symfony2
    #
    def docker_preinstall_sf2(dbname)
      Dir.chdir('app/config')
      system 'cp parameters.yml.dist parameters.yml'

      @technos.each do |techno|
        technoname = techno[:name].sub(/-.*$/,'').downcase
        containername = "#{technoname}_#{@projectname}"

        if /mysql/.match(containername)
          system "perl -pi -e 's/database_host:.*$/database_host: #{containername}/' parameters.yml"
          system "perl -pi -e 's/database_name:.*$/database_name: #{dbname}/' parameters.yml"
          system 'perl -pi -e "s/database_user:.*$/database_user: root/" parameters.yml'
          system 'perl -pi -e "s/database_password:.*$/database_password: 8to9or1/" parameters.yml'
        end

        system "perl -pi -e 's/es_host:.*$/es_host: #{containername}/' parameters.yml" if /elasticsearch/.match(containername)
        system "perl -pi -e 's/amqp_host:.*$/amqp_host: #{containername}/' parameters.yml" if /rabbitmq/.match(containername)
        system "perl -pi -e 's;kibana_url:.*$;kibana_url: \'http://#{containername}/app/kibana\';' parameters.yml" if /kibana/.match(containername)
      end

      @endpoints.each do |ep|
        containername = "ep_#{ep[:path]}_#{@projectname}"
        containerpath = containername.sub(/^ep_/, '').sub(/_.*$/, '')
        system "perl -pi -e 's/#{containerpath}_host:.*$/#{containerpath}_host: #{containername}/' parameters.yml"
      end

      Dir.chdir('../..')
    end

    # Execute postinstall task
    #
    def docker_postinstall
      rootFolder = Dir.pwd

      # execute preinstall cmds
      @endpoints.each do |ep|
        framework = ep[:frameworkname]
        containername = "ep_#{ep[:path]}_#{@projectname}"
        Dir.chdir("#{rootFolder}/#{ep[:path]}")

        # execute framework specific script
        case framework
        when /Symfony/
          port = docker_getport(containername)
          docker_postinstall_sf2("ep_#{ep[:path]}_#{@projectname}", framework.downcase, port)
        when /Drupal/
          docker_postinstall_drupal(ep[:path])
        when /Wordpress/
          port = docker_getport(containername)
          docker_postinstall_wp("ep_#{ep[:path]}_#{@projectname}", ep[:path], port)
        end

        docker_reset_permissions(containername)
      end

      Dir.chdir(rootFolder)
    end

    # Postinstall cmds for drupal project
    #
    def docker_postinstall_drupal(dbname)
      puts "Install Drupal Website"
      # get last container version and execute site-install
      system "docker run --net=#{@projectname}_default  -v=#{Dir.pwd}:/app nextdeploy/drush -y drush -y cim >/dev/null 2>&1"
    end

    # Postinstall cmds for wordpress
    #
    def docker_postinstall_wp(containername, dbname, port)
      # Ugly hack because wordpress docker image
      if Dir.exists?("git-wp-content")
        system "rm -rf wp-content"
        system "mv git-wp-content wp-content"
      end

      email = @user[:email]
      # get last container version and install wordpress website
      system "docker pull nextdeploy/wp"
      system "docker run --net=#{@projectname}_default  -v=#{Dir.pwd}:/app nextdeploy/wp core install --url=http://#{@@docker_ip}:#{port}/ --title=#{@projectname} --admin_user=admin --admin_password=admin --admin_email=#{email}"
      system "docker run --net=#{@projectname}_default  -v=#{Dir.pwd}:/app nextdeploy/wp search-replace --all-tables 'ndwpuri' '#{@@docker_ip}:#{port}'"
      system "docker run --net=#{@projectname}_default  -v=#{Dir.pwd}:/app nextdeploy/wp user update 1 --user_pass=#{@project[:password]}"
    end

    # Postinstall cmds for symfony2 project
    #
    def docker_postinstall_sf2(containername, framework, port)
      # change base domain
      system "perl -pi -e 's/base_hostname:.*$/base_hostname: \'#{@@docker_ip}:#{port}\'/' app/config/parameters.yml"
      system "perl -pi -e 's/base_domain:.*$/base_domain: \'#{@@docker_ip}:#{port}\'/' app/config/parameters.yml"

      docroot = Dir.pwd
      eppath = containername.sub(/^ep_/, '').sub(/_#{@projectname}$/, '')

      # get last container version
      system "docker pull nextdeploy/#{framework}console"

      # Ensure that the first composer has finish before launch symfony commands
      until File.exists?("app/bootstrap.php.cache") do
        puts "Waiting composer finished his work ....."
        sleep 5
      end

      puts "Install symfony website"
      # install and configure doctrine database
      system "docker run --net=#{@projectname}_default -v=#{docroot}:/var/www/html nextdeploy/#{framework}console assets:install --symlink"
    end

    # Execute postinstall script
    #
    def docker_postinstall_script
      system "docker pull nextdeploy/postinstall"
      system "docker run --net=#{@projectname}_default -v=#{Dir.pwd}:/app nextdeploy/postinstall"
    end

    # Run a phpmyadmin container
    #
    def docker_pma
      port = 9381
      until port_open?(@@docker_ip, port) do
        port = port + 1
      end

      system "docker pull nextdeploy/phpmyadmin"

      puts "\n\nPhpmyadmin, http://#{@@docker_ip}:#{port}/"
      puts "Ctrl-c for stop phpmyadmin and get back to terminal prompt"
      exec "docker run --net=#{@projectname}_default -e \"DB_HOST=mysql_#{@projectname}\" -p #{port}:80 nextdeploy/phpmyadmin 1>/dev/null 2>&1"
    end

    # Reset permission on docroot for container identified by containername
    #
    def docker_reset_permissions(containername)
      system "docker exec #{containername} /bin/bash -c '[[ -d /var/www/html ]] && chown -R 1000:1000 /var/www/html;[[ -d /app ]] && chown -R 1000:1000 /app' 2>/dev/null"
    end

    # Get Exposed Port from container name
    #
    def docker_getport(containername)
      %x{docker ps --filter name=#{containername} --format "{{.Ports}}" | sed "s;->.*$;;" | sed "s;^.*:;;" | head -n 1 | tr -d "\n"}
    end

    # Docker check
    #
    def docker_check
      if File.exists?('/usr/local/bin/docker-compose') || File.exists?('/usr/bin/docker-compose')
        if File.exists?('/usr/bin/sw_vers')
          unless docker_native?
            puts "'ndeploy docker' needs 'docker for mac' version instead of 'docker toolbox'"
            puts "You can download from https://download.docker.com/mac/stable/Docker.dmg"
            puts "Otherwise, some important functions are not working"
            sleep 5
          end
        end
      else
        docker_install
      end
    end

    # Get host ip
    #
    def get_docker_ip
      dockerIp = %x{test -n "$DOCKER_HOST" && echo "${DOCKER_HOST}" | sed "s;:.*;;" | tr -d "\n"}
      if dockerIp.empty?
        enIf = %x{netstat -rn | awk '/^0.0.0.0/ {thif=substr($0,74,10); print thif;} /^default.*UG/ {thif=substr($0,65,10); print thif;}' | head -n 1 | sed "s; ;;g" | tr -d "\n"}
        dockerIp = %x{/sbin/ifconfig #{enIf} | grep -Eo 'inet (addr:)?([0-9]*\\.){3}[0-9]*' | grep -Eo '([0-9]*\\.){3}[0-9]*' | grep -v '127.0.0.1' | sed "s; ;;g" | tr -d "\n" | sed "s;inet;;g" | tr -d "\n"}
      end

      dockerIp.sub('tcp://', '')
    end

    # Check if docker native
    #
    def docker_native?
      if File.exists?('/usr/bin/sw_vers')
        if File.exists?('/Applications/Docker.app')
          true
        else
          false
        end
      else
        true
      end
    end

    # Docker install
    #
    def docker_install
      currentFolder = Dir.pwd
      puts "Docker Installation ..."
      Dir.chdir('/tmp')
      if File.exists?('/usr/bin/sw_vers')
        system 'curl -OsSL "https://download.docker.com/mac/stable/Docker.dmg"'
        system 'hdiutil mount Docker.dmg'
        system 'sudo cp -rf /Volumes/Docker/Docker.app /Applications/'
        system 'rm -f Docker.dmg'
        puts "Docker is installed,  please launch Docker app and execute again 'ndeploy docker'"
        exit 0
      else
        system 'wget -qO- https://get.docker.com/ | sudo sh'
        system 'sudo /bin/bash -c \'curl -L https://github.com/docker/compose/releases/download/1.9.0/docker-compose-`uname -s`-`uname -m` > /usr/local/bin/docker-compose\''
        system 'sudo chmod +x /usr/local/bin/docker-compose'
      end
      Dir.chdir(currentFolder)
    end

    # Waiting mariadb is up
    #
    def docker_waiting_containers
      puts "Waiting 40s for ensure that containers are up ..."
      sleep 40
    end

    # Helper function for parse json call
    #
    # @param body [String] the json on input
    # @return [Hash] the json hashed with symbol
    def json(body)
      JSON.parse(body, symbolize_names: true)
    end

    # Init token generate
    #
    def token
      authuser(@email, @password)
    end

    # Return rest headers well formated
    #
    def rest_headers
      { 'Accept' => 'application/json', 'Content-Type' => 'application/json', 'Authorization' => "Token token=#{@user[:authentication_token]}" }
    end

    # Return true if the port is open
    #
    def port_open?(ip, port)
      begin
        Timeout::timeout(1) do
          begin
            s = TCPSocket.new(ip, port)
            s.close
            return false
          rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
            return true
          end
        end
      rescue Timeout::Error
      end

      return true
    end

    # Puts errors on the output
    def error(msg)
      return if @nolog
      puts msg
      exit 5
    end
  end
end

NextDeploy.start(ARGV)
