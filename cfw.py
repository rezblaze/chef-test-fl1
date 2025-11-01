$ sudo smartupdate getattributes --nodes mn053-2hz1-01s43lo.uhc.com
GetAttributes in progress.
Node Attributes: 
    Node: mn053-2hz1-01s43lo.uhc.com - ILO5
        Schedule Information:
            None
        Installation Options:
            rewrite			: false
            downgrade			: false
            firmware			: true
            software			: true
            ignore_warnings		: true
            ignore_tpm			: true
            dryrun			: false
            skip_missing_compsig	: false
            verbose			: false
            failed_dependency		: FORCEINSTALL
            skip_prereqs                : true
        Reboot Options:
            action          : Never
            delay           : 60
            message         : Rebooting at user request in order to activate deployed firmware or software
        iLO Repository Options:
            save_install_set			: false
            install_set_name			: 
            install_set_description		: 
            update_existing_recoveryset 	: false
            manually_manage_iLO_repository	: false
        Baseline:
            /pub/spp/gen10_spp_current/packages
        OS Management Options:
            no management : false
            use ams       : false
            use snmp      : false
            use wmi       : false
