require 'log4r'
require_relative 'esxi_connection'

module VagrantPlugins
  module ESXi
    module Action
      # This action will save (create) a new snapshot
      class SnapshotSave
        def initialize(app, _env)
          @app    = app
          @logger = Log4r::Logger.new('vagrant_vmware_esxi::action::snapshot_save')
        end

        def call(env)
          snapshotsave(env)
          @app.call(env)
        end

        def snapshotsave(env)
          @logger.info('vagrant-vmware-esxi, snapshot_save: start...')

          # Get config.
          machine = env[:machine]
          config = env[:machine].provider_config
          time = Time.new

          @logger.info("vagrant-vmware-esxi, snapshot_save: machine id: #{machine.id}")
          @logger.info("vagrant-vmware-esxi, snapshot_save: current state: #{env[:machine_state]}")

          if env[:machine_state].to_s == 'not_created'
            env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                 message: 'Cannot snapshot_save in this state')
          else
            env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                 message: 'Attempting to snapshot_save')

            env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                 message: "snapshot name      : #{env[:snapshot_name]}")

            if RUBY_PLATFORM =~ /win/i
              username_msg = ENV['USERNAME'] unless ENV['USERNAME'].nil?
            else
              username_msg = ENV['USER'] unless ENV['USER'].nil?
            end
            username_msg = "Unknown" if username_msg.nil?

            options_msg = ''
            options_msg << ' ' + config.guest_snapshot_includememory unless config.guest_snapshot_includememory.nil?
            options_msg << ' ' + config.guest_snapshot_quiesced unless config.guest_snapshot_quiesced.nil?
            options_msg = "Options:" + options_msg if options_msg.length > 2

            snapshot_msg = time.localtime.to_s + ", Snapshot created using Vagrant-vmware-esxi by " +\
                            username_msg + "\n#{options_msg}"

            if config.debug =~ %r{true}i
              env[:ui].info I18n.t('vagrant_vmware_esxi.vagrant_vmware_esxi_message',
                                   message: "snapshot_msg: #{snapshot_msg}")
            end

            r = ESXiConnection.exec!(env, "vim-cmd vmsvc/snapshot.create #{machine.id} "\
              "\"#{env[:snapshot_name]}\" \"#{snapshot_msg}\" "\
              "#{config.guest_snapshot_includememor} #{config.guest_snapshot_quiesced}")

            if r.exitstatus != 0
              raise Errors::ESXiError,
                    message: "Unable to save snapshots of the VM:\n"\
                             "  #{r}"
            end
            env[:ui].info I18n.t('vagrant_vmware_esxi.support')

            env[:ui].info I18n.t('vagrant_vmware_esxi.snapshot_saved')
          end
        end
      end
    end
  end
end
