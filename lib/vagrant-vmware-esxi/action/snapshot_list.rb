require 'log4r'
require_relative 'esxi_connection'

module VagrantPlugins
  module ESXi
    module Action
      # This action will list all the snapshots
      class SnapshotList
        def initialize(app, _env)
          @app    = app
          @logger = Log4r::Logger.new('vagrant_vmware_esxi::action::snapshot_list')
        end

        def call(env)
          snapshotlist(env)
          @app.call(env)
        end

        def snapshotlist(env)
          @logger.info('vagrant-vmware-esxi, snapshot_list: start...')

          # Get config.
          machine = env[:machine]
          config = env[:machine].provider_config

          @logger.info("vagrant-vmware-esxi, snapshot_list: machine id: #{machine.id}")
          @logger.info("vagrant-vmware-esxi, snapshot_list: current state: #{env[:machine_state]}")

          if env[:machine_state].to_s == 'not_created'
           env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                message: 'Cannot snapshot_list in this state')
          else
            r = ESXiConnection.exec!(env,
                "vim-cmd vmsvc/snapshot.get #{machine.id} 2>&1 | "\
                "grep 'Snapshot Name'|sed 's/.*Snapshot Name        : //g'")

            allsnapshots = r
            if r.exitstatus != 0
              raise Errors::ESXiError,
                    message: "Unable to list snapshots:\n"\
                             "  #{allsnapshots}\n#{r.stderr}"
            end

            env[:machine_snapshot_list] = allsnapshots.split("\n")
          end
        end
      end
    end
  end
end
