require 'log4r'
require_relative 'esxi_connection'

module VagrantPlugins
  module ESXi
    module Action
      # This action will Resume (power on) the VM
      class Resume
        def initialize(app, _env)
          @app    = app
          @logger = Log4r::Logger.new('vagrant_vmware_esxi::action::resume')
        end

        def call(env)
          resume(env)
          @app.call(env)
        end

        def resume(env)
          @logger.info('vagrant-vmware-esxi, resume: start...')

          # Get config.
          machine = env[:machine]
          config = env[:machine].provider_config

          @logger.info("vagrant-vmware-esxi, resume: machine id: #{machine.id}")
          @logger.info("vagrant-vmware-esxi, resume: current state: #{env[:machine_state]}")

          if (env[:machine_state].to_s == 'powered_on') ||
             (env[:machine_state].to_s == 'running')
            env[:ui].info I18n.t('vagrant_vmware_esxi.already_powered_on')
          elsif env[:machine_state].to_s == 'not_created'
            env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                message: 'Cannot resume in this state')
          elsif (env[:machine_state].to_s == 'powered_off') ||
                (env[:machine_state].to_s == 'suspended')
            env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                 message: 'Attempting to resume')

            r = ESXiConnection.exec!(env, "vim-cmd vmsvc/power.on #{machine.id}")
            config.saved_ipaddress = nil

            if r.exitstatus != 0
              raise Errors::ESXiError,
                    message: "Unable to resume the VM:\n"\
                             "  #{r}"
            end
            env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                 message: 'VM has been resumed...')
          else
            raise Errors::ESXiError, message: 'Unknown state to resume...'
          end
        end
      end
    end
  end
end
