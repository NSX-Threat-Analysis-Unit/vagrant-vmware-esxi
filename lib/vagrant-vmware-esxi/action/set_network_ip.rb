require 'log4r'
require 'base64'
require 'vagrant/util/network_ip'
require "vagrant/util/scoped_hash_override"
require_relative 'esxi_connection'

module VagrantPlugins
  module ESXi
    module Action
      # This action set the IP address  (do the config.vm_network settings...)
      class SetNetworkIP
        include Vagrant::Util::NetworkIP
        include Vagrant::Util::ScopedHashOverride

        def initialize(app, env)
          @app    = app
          @logger = Log4r::Logger.new('vagrant_vmware_esxi::action::set_network_ip')
        end

        def call(env)
          set_network_ip(env)
          @app.call(env)
        end

        def set_network_ip(env)
          @logger.info('vagrant-vmware-esxi, set_network_ip: start...')

          # Get config.
          @env = env
          machine = env[:machine]
          config = env[:machine].provider_config

          # Wait for SSH to be ready before attempting network configuration
          wait_for_ssh_ready(env)

          #  Number of nics configured
          if config.esxi_virtual_network.is_a? Array
            number_of_adapters = config.esxi_virtual_network.count
          else
            number_of_adapters = 1
          end

          #
          #  Make an array of vm.network settings (from Vagrantfile).
          #  One index for each network interface. I'll use private_network and
          #  public_network as both valid.   Since it would be a TERRIBLE idea
          #  to modify ESXi virtual network configurations, I'll just set the IP
          #  using static or DHCP.   Everything else will be ignored...
          #
          vm_network = []
          env[:machine].config.vm.networks.each do |type, options|
            # I only handle private and public networks
            next if type != :private_network && type != :public_network
            next if vm_network.count >= number_of_adapters
            vm_network << options
          end

          if (config.debug =~ %r{true}i)
            puts "num adapters: #{number_of_adapters},  vm.network.count: #{vm_network.count}"
          end

          networks_to_configure = []
          if (number_of_adapters > 1) and (vm_network.count > 0)
            1.upto(number_of_adapters - 1) do |index|
              if !vm_network[index - 1].nil?
                options = vm_network[index - 1]
                next if options[:auto_config] === false
                if options[:ip]
                  ip_class = options[:ip].gsub(/\..*$/,'').to_i
                  if ip_class < 127
                    class_netmask = '255.0.0.0'
                  elsif ip_class > 127 and ip_class < 192
                    class_netmask = '255.255.0.0'
                  elsif ip_class >= 192 and ip_class <= 223
                    class_netmask = '255.255.255.0'
                  end

                  # if netmask is not specified or is invalid, use, class defaults
                  unless options[:netmask]
                     netmask = class_netmask
                  else
                    netmask = options[:netmask]
                  end
                  unless netmask =~ /^(((128|192|224|240|248|252|254)\.0\.0\.0)|(255\.(0|128|192|224|240|248|252|254)\.0\.0)|(255\.255\.(0|128|192|224|240|248|252|254)\.0)|(255\.255\.255\.(0|128|192|224|240|248|252|254)))$/i
                    env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                         message: "WARNING         : Invalid netmask specified, using Class mask (#{class_netmask})")
                    netmask = class_netmask
                  end
                  network = {
                    interface: index,
                    type: :static,
                    use_dhcp_assigned_default_route: options[:use_dhcp_assigned_default_route],
                    guest_mac_address: options[:mac],
                    ip: options[:ip],
                    netmask: netmask,
                    gateway: options[:gateway]
                  }
                  ip_msg = options[:ip] + '/'
                else
                  network = {
                    interface: index,
                    type: :dhcp,
                    use_dhcp_assigned_default_route: options[:use_dhcp_assigned_default_route],
                    guest_mac_address: options[:mac]
                  }
                  ip_msg = 'dhcp'
                  netmask = ''
                end
                networks_to_configure << network
                @logger.debug("networks_to_configure: #{networks_to_configure.inspect}")
                env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                     message: "Configuring     : #{ip_msg}#{netmask} on #{config.esxi_virtual_network[index]}")
              end
            end

            #
            #  Configure networks based on guest OS type
            #
            sleep(1)
            if windows_guest?(env)
              configure_windows_networks(env, networks_to_configure)
            else
              # Disable cloud-init network configuration if present
              disable_cloud_init_network(env)
              env[:machine].guest.capability(
                  :configure_networks, networks_to_configure)
            end
          end
        end

        private

        # Wait for SSH to be ready with exponential backoff
        def wait_for_ssh_ready(env)
          machine = env[:machine]
          config = env[:machine].provider_config
          max_retries = 10
          retry_count = 0
          base_delay = 3

          @logger.info("Waiting for SSH to be ready...")
          env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                               message: "Waiting for SSH to be ready...")

          loop do
            begin
              # Try a simple test command
              result = machine.communicate.test("echo 'SSH Ready'", sudo: false)
              if result
                @logger.info("SSH is ready!")
                env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                     message: "SSH is ready")
                return true
              end
            rescue => e
              # Catch all SSH-related errors
              retry_count += 1
              if retry_count <= max_retries
                delay = base_delay * (2 ** (retry_count - 1)) # Exponential backoff: 3, 6, 12, 24, 48...
                delay = [delay, 60].min # Cap at 60 seconds
                @logger.debug("SSH not ready (attempt #{retry_count}/#{max_retries}): #{e.class} - #{e.message}")
                env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                     message: "SSH not ready, waiting #{delay}s (attempt #{retry_count}/#{max_retries})...")
                sleep(delay)
                next # Continue to next iteration of loop
              else
                @logger.error("SSH failed to become ready after #{max_retries} attempts: #{e.class} - #{e.message}")
                env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                     message: "WARNING         : SSH not ready after #{max_retries} attempts, continuing anyway...")
                return false
              end
            end
          end
        end

        # Disable cloud-init network configuration if cloud-init is present
        # This prevents cloud-init from overriding Vagrant's network settings on reboot
        def disable_cloud_init_network(env)
          machine = env[:machine]

          # Check if cloud-init is installed
          unless machine.communicate.test("command -v cloud-init >/dev/null 2>&1")
            @logger.debug("cloud-init not detected, skipping")
            return
          end

          @logger.info("cloud-init detected, disabling network configuration")

          # Create config to disable cloud-init network management
          # This file tells cloud-init to not touch network configuration
          config_path = "/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg"

          begin
            # Check if already disabled
            if machine.communicate.test("test -f #{config_path}")
              @logger.debug("cloud-init network already disabled")
            else
              # Write the disable config using a here-doc to avoid quoting issues
              machine.communicate.sudo("mkdir -p /etc/cloud/cloud.cfg.d")
              machine.communicate.sudo("cat > #{config_path} << 'EOF'\nnetwork: {config: disabled}\nEOF")

              env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                   message: "Disabled cloud-init network config")
            end

            # Always remove cloud-init's netplan config if it exists (it may conflict)
            if machine.communicate.test("test -f /etc/netplan/50-cloud-init.yaml")
              machine.communicate.sudo("rm -f /etc/netplan/50-cloud-init.yaml")
              # Re-apply netplan after removing cloud-init config
              machine.communicate.sudo("netplan apply 2>/dev/null || true")
              env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                   message: "Removed cloud-init netplan config")
            end
          rescue => e
            @logger.warn("Failed to disable cloud-init network: #{e.message}")
            env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                 message: "WARNING         : Failed to disable cloud-init: #{e.message}")
          end
        end

        # Detect if the guest is a Windows machine
        def windows_guest?(env)
          # Check using Vagrant's guest detection
          begin
            guest_name = env[:machine].guest.name.to_s.downcase
            return true if guest_name.include?('windows')
          rescue
            # Guest detection might fail, fall through to other methods
          end

          # Check the configured guest OS type
          config = env[:machine].provider_config
          if config.guest_guestos
            guestos = config.guest_guestos.to_s.downcase
            return true if guestos.start_with?('win') || guestos.include?('windows')
          end

          false
        end

        # Get MAC addresses for network adapters from ESXi
        def get_adapter_mac_addresses(env)
          machine = env[:machine]
          mac_addresses = {}

          # Query VMware for guest NIC info - extract all MAC addresses
          # The NICs are listed in order (ethernet0, ethernet1, etc.)
          cmd = "vim-cmd vmsvc/get.guest #{machine.id} 2>/dev/null | " \
                "grep 'macAddress = ' | grep -oE '\"[0-9a-fA-F:]+\"'"
          result = ESXiConnection.exec!(env, cmd)

          adapter_index = 0
          result.to_s.each_line do |line|
            if line =~ /"([0-9a-fA-F:]+)"/
              mac = $1.downcase
              mac_addresses[adapter_index] = mac
              @logger.debug("Found MAC for adapter #{adapter_index}: #{mac}")
              adapter_index += 1
            end
          end

          @logger.debug("Detected MAC addresses: #{mac_addresses.inspect}")
          mac_addresses
        end

        # Configure network adapters on Windows guests using PowerShell
        # Workaround for https://github.com/hashicorp/vagrant/issues/12742
        def configure_windows_networks(env, networks)
          machine = env[:machine]
          config = env[:machine].provider_config

          # Get MAC addresses from ESXi
          mac_addresses = get_adapter_mac_addresses(env)

          # Wait for WinRM/SSH to be ready
          env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                               message: "Configuring Windows network adapters...")

          networks.each do |network|
            adapter_index = network[:interface]
            mac = mac_addresses[adapter_index]

            unless mac
              @logger.warn("Could not find MAC address for adapter #{adapter_index}")
              env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                   message: "WARNING         : Could not find MAC for adapter #{adapter_index}")
              next
            end

            # Format MAC for PowerShell (Windows uses dashes)
            mac_for_ps = mac.gsub(':', '-').upcase

            if network[:type] == :static
              configure_windows_static_ip(env, mac_for_ps, network)
            else
              configure_windows_dhcp(env, mac_for_ps, adapter_index)
            end
          end
        end

        # Configure a static IP on a Windows adapter identified by MAC address
        def configure_windows_static_ip(env, mac, network)
          machine = env[:machine]
          ip = network[:ip]
          netmask = network[:netmask]
          gateway = network[:gateway]

          # Convert netmask to prefix length (e.g., 255.255.255.0 -> 24)
          prefix_length = netmask_to_prefix(netmask)

          # PowerShell script to configure the adapter
          # Find adapter by MAC, remove existing IP config, set new static IP
          ps_script = <<~PS
            $ErrorActionPreference = 'Stop'
            $mac = '#{mac}'
            $adapter = Get-NetAdapter | Where-Object { $_.MacAddress -eq $mac }
            if (-not $adapter) {
                Write-Error "Adapter with MAC $mac not found"
                exit 1
            }
            $ifIndex = $adapter.InterfaceIndex

            # Remove existing IP addresses on this adapter
            Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

            # Remove existing default gateway if any
            Get-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

            # Set the new static IP
            New-NetIPAddress -InterfaceIndex $ifIndex -IPAddress '#{ip}' -PrefixLength #{prefix_length} -ErrorAction Stop
          PS

          # Add gateway if specified
          if gateway && !gateway.empty?
            ps_script += <<~PS

              # Set default gateway
              New-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix '0.0.0.0/0' -NextHop '#{gateway}' -ErrorAction SilentlyContinue
            PS
          end

          ps_script += <<~PS

            Write-Host "Configured adapter $($adapter.Name) with IP #{ip}/#{prefix_length}"
          PS

          @logger.debug("Configuring Windows static IP: #{ip}/#{prefix_length} on MAC #{mac}")

          begin
            execute_powershell(machine, ps_script)
            env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                 message: "Configured      : #{ip}/#{prefix_length} on adapter #{mac}")
          rescue => e
            @logger.error("Failed to configure Windows network: #{e.message}")
            env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                 message: "WARNING         : Failed to configure #{ip} - #{e.message}")
          end
        end

        # Configure DHCP on a Windows adapter identified by MAC address
        def configure_windows_dhcp(env, mac, adapter_index)
          machine = env[:machine]

          ps_script = <<~PS
            $ErrorActionPreference = 'Stop'
            $mac = '#{mac}'
            $adapter = Get-NetAdapter | Where-Object { $_.MacAddress -eq $mac }
            if (-not $adapter) {
                Write-Error "Adapter with MAC $mac not found"
                exit 1
            }

            # Enable DHCP
            Set-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -Dhcp Enabled -ErrorAction SilentlyContinue

            # Remove any static IPs
            Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.PrefixOrigin -eq 'Manual' } |
                Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

            Write-Host "Enabled DHCP on adapter $($adapter.Name)"
          PS

          @logger.debug("Configuring Windows DHCP on MAC #{mac}")

          begin
            execute_powershell(machine, ps_script)
            env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                 message: "Configured      : DHCP on adapter #{mac}")
          rescue => e
            @logger.error("Failed to configure Windows DHCP: #{e.message}")
            env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                 message: "WARNING         : Failed to configure DHCP - #{e.message}")
          end
        end

        # Execute a PowerShell script on Windows using Base64 encoding to avoid escaping issues
        def execute_powershell(machine, script)
          # Encode script as Base64 UTF-16LE for PowerShell's -EncodedCommand
          encoded = Base64.strict_encode64(script.encode('UTF-16LE'))
          machine.communicate.execute("powershell -ExecutionPolicy Bypass -EncodedCommand #{encoded}")
        end

        # Convert netmask to CIDR prefix length
        def netmask_to_prefix(netmask)
          octets = netmask.split('.').map(&:to_i)
          binary = octets.map { |o| o.to_s(2).rjust(8, '0') }.join
          binary.count('1')
        end
      end
    end
  end
end
