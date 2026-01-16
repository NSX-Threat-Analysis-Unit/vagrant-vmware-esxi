require 'net/ssh'
require 'log4r'

module VagrantPlugins
  module ESXi
    module Action
      # Helper module for managing SSH connections to ESXi hosts.
      #
      # Design goals:
      # - Support parallel VM operations (each machine gets its own connection)
      # - Automatic reconnection on stale/dead connections
      # - Thread-safe connection management
      #
      # Usage:
      #   # Preferred - uses automatic reconnection on failure:
      #   result = ESXiConnection.exec!(env, "vim-cmd vmsvc/getallvms")
      #
      #   # For multiple commands in sequence, get a session:
      #   ESXiConnection.with_session(env) do |ssh|
      #     ssh.exec!("command1")
      #     ssh.exec!("command2")
      #   end
      module ESXiConnection
        # Connection pool keyed by "host:port" - shared across all VMs on same host
        # This mimics OpenSSH ControlMaster behavior
        @@connections = {}
        @@mutex = Mutex.new
        @@at_exit_registered = false
        @@logger = Log4r::Logger.new('vagrant_vmware_esxi::action::esxi_connection')

        # Register at_exit hook to close all connections when Ruby exits
        def self.register_at_exit
          return if @@at_exit_registered
          @@at_exit_registered = true
          at_exit do
            close_all_connections
          end
        end

        # Build connection key - shared per ESXi host
        def self.connection_key(env)
          config = env[:machine].provider_config
          "#{config.esxi_hostname}:#{config.esxi_hostport}"
        end

        # Create a new SSH connection to ESXi host
        def self.create_connection(env)
          config = env[:machine].provider_config
          key = connection_key(env)

          @@logger.debug("Opening SSH connection to #{key}")

          max_retries = 3
          retry_count = 0

          begin
            ssh = Net::SSH.start(config.esxi_hostname, config.esxi_username,
              password:                   config.esxi_password,
              port:                       config.esxi_hostport,
              keys:                       config.local_private_keys,
              timeout:                    30,
              number_of_password_prompts: 0,
              non_interactive:            true,
              keepalive:                  true,
              keepalive_interval:         30
            )

            @@mutex.synchronize do
              # Close any existing connection for this key
              if @@connections[key] && !@@connections[key].closed?
                begin
                  @@connections[key].close
                rescue
                  # Ignore errors when closing old connection
                end
              end
              @@connections[key] = ssh
            end

            register_at_exit
            @@logger.debug("SSH connection established for #{key}")
            ssh
          rescue Net::SSH::Exception, Errno::ECONNRESET, Errno::ECONNREFUSED, Errno::ETIMEDOUT, IOError => e
            retry_count += 1
            if retry_count <= max_retries
              @@logger.debug("Connection failed: #{e.message}. Retrying in #{retry_count * 2}s...")
              sleep(retry_count * 2)
              retry
            else
              raise
            end
          end
        end

        # Get an SSH connection, creating new or reusing existing if healthy
        def self.get_connection(env)
          key = connection_key(env)

          @@mutex.synchronize do
            existing = @@connections[key]
            if existing && !existing.closed?
              return existing
            end
          end

          # Create new connection outside mutex to avoid blocking
          create_connection(env)
        end

        # Execute a command with automatic reconnection on failure.
        # This is the preferred method for running commands.
        def self.exec!(env, command)
          max_retries = 2
          retry_count = 0

          begin
            ssh = get_connection(env)
            ssh.exec!(command)
          rescue Net::SSH::Exception, Errno::ECONNRESET, Errno::EPIPE, IOError => e
            retry_count += 1
            if retry_count <= max_retries
              @@logger.debug("Command failed: #{e.message}. Reconnecting...")
              close_connection(env)
              sleep(1)
              retry
            else
              raise
            end
          end
        end

        # Execute multiple commands within a session block with automatic reconnection.
        # Use this when you need direct SSH access (e.g., for open_channel).
        def self.with_session(env, &block)
          max_retries = 2
          retry_count = 0

          begin
            ssh = get_connection(env)
            yield ssh
          rescue Net::SSH::Exception, Errno::ECONNRESET, Errno::EPIPE, IOError => e
            retry_count += 1
            if retry_count <= max_retries
              @@logger.debug("Session failed: #{e.message}. Reconnecting...")
              close_connection(env)
              sleep(1)
              retry
            else
              raise
            end
          end
        end

        # Close the SSH connection for a specific machine.
        # The next get_connection or exec! call will create a fresh connection.
        def self.close_connection(env)
          key = connection_key(env)

          @@mutex.synchronize do
            if @@connections[key]
              begin
                @@connections[key].close unless @@connections[key].closed?
              rescue
                # Ignore errors when closing
              end
              @@connections.delete(key)
              @@logger.debug("Connection closed for #{key}")
            end
          end
        end

        # Close all connections (for cleanup)
        def self.close_all_connections
          @@mutex.synchronize do
            @@connections.each do |key, ssh|
              begin
                unless ssh.closed?
                  @@logger.debug("Closing SSH connection for #{key}")
                  ssh.close
                end
              rescue => e
                # Ignore errors when closing
                @@logger.debug("Error closing #{key}: #{e.message}")
              end
            end
            @@connections.clear
          end
        end
      end
    end
  end
end
