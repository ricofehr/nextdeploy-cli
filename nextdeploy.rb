#!/usr/bin/env ruby
# encoding: utf-8
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

class NextDeploy < Thor
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
  map update: :upgrade

  # upgrade ndeploy
  #
  desc "upgrade [--force]", "upgrade ndeploy with the last version"
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
  desc "up", "launch current commit to remote nextdeploy"
  def up
    init

    # ensure requirements
    unless @project
      warn("Git repository for #{gitpath} not found, have-you already import this project ?")
      exit
    end

    # prepare post request
    launch_req = { vm: { project_id: @project[:id], vmsize_id: @project[:vmsizes][0], user_id: @user[:id], systemimage_id: @project[:systemimages][0], technos: @project[:technos], is_auth: true, is_prod: false, is_cached: false, is_backup: false, is_ht: @project[:is_ht], layout: @user[:layout], htlogin: @project[:login], htpassword: @project[:password], commit_id: commitid } }

    response = @conn.post do |req|
      req.url "/api/v1/vms/short"
      req.headers = rest_headers
      req.body = launch_req.to_json
    end

    json(response.body)[:vm]
  end

  # Display logs for a vm
  #
  desc "logs [idvm]", "Display some logs for vm identified by [idvm] (view ndeploy list), or current vm or last vm by default (if idvm is missing)"
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
  desc "details [idvm]", "Display some details for vm identified by [idvm] (view ndeploy list), or current vm or last vm by default (if idvm is missing)"
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
    puts "Samba Share: smb://modem:#{vmtodetails[:term_password]}@#{vmtodetails[:floating_ip]}/#{vmtodetails[:name].gsub(/\..*$/,'')}"
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
  desc "folder [idvm] [workspace]", "share project folder from vm identified by [idvm] (see ndeploy list), to local created folder (parent is current directory or [workspace] parameter)"
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
  desc "launch [projectname] [branch]", "launch [branch] (default is master) for [projectname] into a remote vm"
  def launch(projectname=nil, branch='master')
    init

    # ensure requirements
    error("Argument projectname is missing") unless projectname
    error("No projects for #{@user[:email]}") if @projects.empty?

    # select project following parameter
    proj = @projects.select { |p| p[:name] == projectname }
    # return if parameter is invalid
    error("Project #{projectname} not found") if !proj || proj.empty?
    @project = proj[0]

    # get branch from api server
    get_branche(branch)
    error("Branch #{branch} not found") if !@branche
    
    # prepare post request
    launch_req = { vm: { project_id: @project[:id], vmsize_id: @project[:vmsizes][0], user_id: @user[:id], technos: @project[:technos], systemimage_id: @project[:systemimages][0], is_auth: true, is_prod: false, is_cached: false, is_backup: false, is_ht: @project[:is_ht], layout: @user[:layout], htlogin: @project[:login], htpassword: @project[:password], commit_id: "#{@branche[:commits][0]}" } }

    response = @conn.post do |req|
      req.url "/api/v1/vms/short"
      req.headers = rest_headers
      req.body = launch_req.to_json
    end

    json(response.body)[:vm]
  end

  # Destroy a vm
  #
  desc "destroy [idvm]", "destroy remote vm wit [idvm] (see ndeploy list) current vm by default"
  def destroy(idvm=nil)
    init

    vmtodestroy = @vm
    if idvm
      vmtodestroy = @vms.select { |vm| vm[:id].to_i == idvm.to_i && vm[:user] == @user[:id] }[0]
    end

    # ensure requirements
    unless vmtodestroy
      warn("No vm for commit #{commitid}")
      exit
    end

    response = @conn.delete do |req|
      req.url "/api/v1/vms/#{vmtodestroy[:id]}"
      req.headers = rest_headers
    end
  end

  # List current active vms
  #
  desc "list [--all] [--head n]", "list launched vms for current user."
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
  desc "clone [projectname]", "clone project in current folder"
  def clone(projectname=nil)
    init

    # ensure requirements
    error("Argument projectname is missing") unless projectname
    error("No projects for #{@user[:email]}") if @projects.empty?

    # select project following parameter
    proj = @projects.select { |p| p[:name] == projectname }
    # return if parameter is invalid
    error("Project #{projectname} not found") if !proj || proj.empty?
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

    unless File.exist?("#{Dir.home}/.ssh/id_rsa.pub")
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
  desc "ssh [idvm]", "ssh into remote vm with [idvm] (view ndeploy list) or current vm by default"
  def ssh(idvm=nil)
    init

    if idvm
      vmtossh = @vms.select { |vm| vm[:id].to_i == idvm.to_i }[0]
    else
      vmtossh = @vm ? @vm : @vms.select { |vm| vm[:user] == @user[:id] }.sort_by {|v| v[:id]}.reverse.first
    end

    # ensure requirement
    error("No vm for commit #{commitid}") unless vmtossh

    exec "ssh modem@#{vmtossh[:floating_ip]}"
  end

  # Upload an asset archive or a sql/mongo dump onto ftp repository dedicated to project
  #
  desc "putftp assets|dump [--branch b] [--pathuri p] [project] [file]", "putftp an assets archive [file] or a dump [file] for the [project]"
  option :branch
  option :pathuri
  def putftp(typefile=nil, projectname=nil, file=nil)
    init

    # ensure requirement
    error("You must provide type of file to push: assets or dump") unless typefile
    error("You must provide type of file to push: assets or dump") if typefile == 'backup'
    error("Argument projectname is missing") unless projectname
    error("File to push is missing") unless file
    error("No projects for #{@user[:email]}") if @projects.empty?

    # rename file or let as it is
    isrename = (options[:branch] && options[:pathuri]) ? true : false
    # select project following parameter
    proj = @projects.select { |p| p[:name] == projectname }
    # return if parameter is invalid
    error("Project #{projectname} not found") if !proj || proj.empty?
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
    error("File #{file} not found") unless File.exist?(file)
    Net::FTP.open(@ftpendpoint, login_ftp, password_ftp) do |ftp|
      ftp.putbinaryfile(ftp_file, "#{typefile}/#{ftp_filename}")
    end

  end

  # Download an asset archive or a sql/mongo dump from ftp repository dedicated to project
  #
  desc "getftp assets|dump|backup [project] [file]", "get an assets archive or a dump (file or default) for the [project]"
  def getftp(typefile=nil, projectname=nil, file=nil)
    init

    # ensure requirement
    error("You must provide type of file to push: assets, backup or dump") unless typefile
    error("Argument projectname is missing") unless projectname
    error("No projects for #{@user[:email]}") if @projects.empty?

    # select project following parameter
    proj = @projects.select { |p| p[:name] == projectname }
    # return if parameter is invalid
    error("Project #{projectname} not found") if !proj || proj.empty?

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
  desc "listftp assets|dump|backup [project]", "list assets archive or a dump for the [project]"
  def listftp(typefile=nil, projectname=nil, file=nil)
    init

    # ensure requirement
    error("You must provide type of file to push: assets or dump") unless typefile
    error("Argument projectname is missing") unless projectname
    error("No projects for #{@user[:email]}") if @projects.empty?

    # select project following parameter
    proj = @projects.select { |p| p[:name] == projectname }
    # return if parameter is invalid
    error("Project #{projectname} not found") if !proj || proj.empty?
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
      @@version = "1.4"
      @@remote_cli = "http://cli.nextdeploy.io"
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

    # Get current project follow the gitpath value
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
        return
      end

      @project = json(response.body)[:project]
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
    # @params [Array[Integer]] id array
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
    # @params [Array[Integer]] id array
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
    # @params [Array[Integer]] id array
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
    # @params [Array[Integer]] id array
    # No return
    def init_systems
      response = @conn.get do |req|
        req.url "/api/v1/systemimages"
        req.headers = rest_headers
      end

      @systems = json(response.body)[:systemimages]
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

    # Puts errors on the output
    def error(msg)
      return if @nolog
      puts msg
      exit 5
    end
  end
end

NextDeploy.start(ARGV)
