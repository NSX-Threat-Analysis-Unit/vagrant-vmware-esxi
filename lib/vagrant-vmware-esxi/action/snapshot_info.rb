require 'log4r'
require_relative 'esxi_connection'

module VagrantPlugins
  module ESXi
    module Action
      # This action will list all the snapshots
      class SnapshotInfo
        def initialize(app, _env)
          @app    = app
          @logger = Log4r::Logger.new('vagrant_vmware_esxi::action::snapshot_info')
        end

        def call(env)
          snapshotinfo(env)
          @app.call(env)
        end

        def snapshotinfo(env)
          @logger.info('vagrant-vmware-esxi, snapshot_info: start...')

          # Get config.
          machine = env[:machine]
          config = env[:machine].provider_config

          @logger.info("vagrant-vmware-esxi, snapshot_info: machine id: #{machine.id}")
          @logger.info("vagrant-vmware-esxi, snapshot_info: current state: #{env[:machine_state]}")

          if machine.id == ''
            env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                 message: 'Cannot snapshot-info in this state')
          else
            r = ESXiConnection.exec!(env,
                "vim-cmd vmsvc/snapshot.get #{machine.id} 2>&1 | "\
                "sed 's/Get Snapshot:/ /g' | "\
                "grep -v -e '^  $' "\
                "-e 'Snapshot Id ' "\
                "-e 'Snapshot Created On ' "\
                "-e 'Snapshot State '")

            snapshotinfo = r
            if r.exitstatus != 0
              raise Errors::ESXiError,
                    message: "Unable to list snapshots:\n"\
                             "  #{allsnapshots}\n#{r.stderr}"
            end

            env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                 message: "#{snapshotinfo}")
          end
        end
      end
    end
  end
end
