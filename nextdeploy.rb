#!/usr/bin/env ruby

require 'thor'
require 'faraday'
require 'active_support'
require 'active_support/core_ext'
require 'uri'
require 'net/ftp'

class NextDeploy < Thor
  # Launch current commit into a new vms on nextdeploy cloud
  #
  desc "up", "launch current commit to remote nextdeploy"
  def up
    init

    if ! @project
      warn("Git repository for #{gitpath} not found, have-you already import this project ?")
      exit
    end

    # get systemimage
    system = @systems.select { |s| s[:systemimagetype] == @project[:systemimagetype] }[0]
    # prepare post request
    launch_req = { vm: { project_id: @project[:id], vmsize_id: @project[:vmsizes][0], user_id: @user[:id], systemimage_id: system[:id], commit_id: commitid } }

    response = @conn.post do |req|
      req.url "/api/v1/vms"
      req.headers = rest_headers
      req.body = launch_req.to_json
    end

    json(response.body)[:vm]
  end

  # Launch a setted commit into a new vm on nextdeploy cloud
  #
  desc "launch [projectname] [branch] [commit]", "launch [commit] (default is head) on the [branch] (default is master) for [projectname] into remote nextdeploy"
  def launch(projectname=nil, branch='master', commit='HEAD')
    init

    if projectname == nil
      error("Argument projectname is missing")
    end

    if @projects.empty?
      error("No projects for #{@user[:email]}")
    end

    # select project following parameter
    proj = @projects.select { |p| p[:name] == projectname }
    # return if parameter is invalid
    error("Project #{projectname} not found") if !proj || proj.empty?
    @project = proj[0]

    # get well systemimage
    system = @systems.select { |s| s[:systemimagetype] == @project[:systemimagetype] }[0]
    # prepare post request
    launch_req = { vm: { project_id: @project[:id], vmsize_id: @project[:vmsizes][0], user_id: @user[:id], systemimage_id: system[:id], commit_id: "#{@project[:id]}-#{branch}-#{commit}" } }

    response = @conn.post do |req|
      req.url "/api/v1/vms"
      req.headers = rest_headers
      req.body = launch_req.to_json
    end

    json(response.body)[:vm]
  end

  # Destroy current vm
  #
  desc "destroy", "destroy current vm"
  def destroy
    init

    if ! @vm
      warn("No vm for commit #{commitid}")
      exit
    end

    response = @conn.delete do |req|
      req.url "/api/v1/vms/#{@vm[:id]}"
      req.headers = rest_headers
    end
  end

  # List current active vms
  #
  desc "list", "list launched vms for current user"
  def list
    init

    if @vms.empty?
      error("No vms for #{@user[:email]}")
    end

    @vms.each do |vm|
      project = @projects.select { |project| project[:id] == vm[:project] }
      status = "RUNNING"
      status = "SETUP" if vm[:status] < 0
      status = "ERROR" if vm[:status] == 1
      puts "#{project[0][:name]}, #{vm[:commit].gsub(/^[0-9]+-/, '')[0,16]}, #{status}"
    end
  end

  # List projects for current user
  #
  desc "projects", "list projects for current user"
  def projects
    init

    if @projects.empty?
      error("No projects for #{@user[:email]}")
    end

    @projects.sort_by! { |project| project[:name] }
    @projects.each { |project| puts "#{project[:name]}" }
  end

  # Clone a project by his name
  #
  desc "clone [projectname]", "clone project in current folder"
  def clone(projectname=nil)
    init

    if projectname == nil
      error("Argument projectname is missing")
    end

    if @projects.empty?
      error("No projects for #{@user[:email]}")
    end

    # select project following parameter
    proj = @projects.select { |p| p[:name] == projectname }
    # return if parameter is invalid
    error("Project #{projectname} not found") if !proj || proj.empty?
    # else clone the project
    @project = proj[0]
    exec "git clone git@#{@project[:gitpath]}"
  end

  # Ssh into remote vm
  #
  desc "ssh", "ssh into remote vm"
  def ssh
    init

    if ! @vm
      error("No vm for commit #{commitid}")
    end

    exec "ssh modem@#{@vm[:floating_ip]}"
  end

  # Upload an asset archive or a sql/mongo dump onto ftp repository dedicated to project
  #
  desc "putftp assets|dump [project] [file]", "putftp an assets archive [file] or a dump [file] for the [project]"
  def putftp(typefile=nil, projectname=nil, file=nil)
    init

    if typefile == nil
      error("You must provide type of file to push: assets or dump")
    end

    if projectname == nil
      error("Argument projectname is missing")
    end

    if file == nil
      error("File to push is missing")
    end

    if @projects.empty?
      error("No projects for #{@user[:email]}")
    end

    # select project following parameter
    proj = @projects.select { |p| p[:name] == projectname }
    # return if parameter is invalid
    error("Project #{projectname} not found") if !proj || proj.empty?
    @project = proj[0]

    if typefile == 'assets'
      ftp_filename = 'assets.tar.gz'
    else
      ftp_filename = 'dump.sql.gz'
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
  desc "getftp assets|dump [project]", "get an assets archive or a dump for the [project]"
  def getftp(typefile=nil, projectname=nil, file=nil)
    init

    if typefile == nil
      error("You must provide type of file to push: assets or dump")
    end

    if projectname == nil
      error("Argument projectname is missing")
    end

    if @projects.empty?
      error("No projects for #{@user[:email]}")
    end

    # select project following parameter
    proj = @projects.select { |p| p[:name] == projectname }
    # return if parameter is invalid
    error("Project #{projectname} not found") if !proj || proj.empty?
    @project = proj[0]

    if typefile == 'assets'
      ftp_filename = 'assets.tar.gz'
    else
      ftp_filename = 'dump.sql.gz'
    end

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
  desc "listftp assets|dump [project]", "list assets archive or a dump for the [project]"
  def listftp(typefile=nil, projectname=nil, file=nil)
    init

    if typefile == nil
      error("You must provide type of file to push: assets or dump")
    end

    if projectname == nil
      error("Argument projectname is missing")
    end

    if @projects.empty?
      error("No projects for #{@user[:email]}")
    end

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
      open(ENV['HOME']+'/.nextdeploy.conf', 'w') do |f|
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

  # Execute git command
  #
  desc "git [cmd]", "Executes a git command"
  def git(cmd=nil)
    exec "git #{cmd}"
  end

  no_commands do

    # Init datas
    #
    def init
      init_properties
      init_conn
      token
      init_brands
      init_frameworks
      init_systems
      get_project
      get_vm
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
      elsif File.exists?(ENV['HOME']+'/.nextdeploy.conf')
        fp = File.open(ENV['HOME']+'/.nextdeploy.conf', 'r')
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
      if gitp.empty?
        return
      end

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

    # get he vm for current commit
    #
    # No params
    # @return [Array[String]] json output for a vm
    def get_vm

      # if we are not into git project, return
      gitp = gitpath
      if gitp.empty?
        return
      end

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
        faraday.adapter  Faraday.default_adapter
      end
    end

    # Authenticate user
    #
    # @param [String] email of the user
    # @param [String] password of the user
    # No return
    def authuser(email, password)
      auth_req = { email: email, password: password }

      begin
        response = @conn.post do |req|
         req.url "/api/v1/users/sign_in"
         req.headers['Content-Type'] = 'application/json'
         req.headers['Accept'] = 'application/json'
         req.body = auth_req.to_json
        end
      rescue Exception => e
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
      init_vms(@user[:vms])
      init_projects(@user[:projects])
      if @user[:sshkeys][0]
        init_sshkeys(@user[:sshkeys])
      else
        @ssh_key = { name: 'nosshkey' }
      end
    end

    # Get all projects properties
    #
    # @params [Array[Integer]] id array
    # No return
    def init_projects(project_ids)
      @projects = []

      project_ids.each do |project_id|
        response = @conn.get do |req|
          req.url "/api/v1/projects/#{project_id}"
          req.headers = rest_headers
        end

        @projects.push(json(response.body)[:project])
      end
    end

    # Get all vms properties
    #
    # @params [Array[Integer]] id array
    # No return
    def init_vms(vm_ids)
      @vms = []

      vm_ids.each do |vm_id|
        response = @conn.get do |req|
          req.url "/api/v1/vms/#{vm_id}"
          req.headers = rest_headers
        end

        @vms.push(json(response.body)[:vm])
      end
    end

    # Get all sshkeys properties
    #
    # @params [Array[Integer]] id array
    # No return
    def init_sshkeys(ssh_ids)
      @ssh_keys = []

      ssh_ids.each do |ssh_id|
        response = @conn.get do |req|
          req.url "/api/v1/sshkeys/#{ssh_id}"
          req.headers = rest_headers
        end

        @ssh_keys << json(response.body)[:sshkey]
        @ssh_key = @ssh_keys.first
      end
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
