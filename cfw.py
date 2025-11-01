2025-11-01 12:41:57,707 INFO   run() L33   starting build for id: c18f50aa-223c-463e-a9e2-3f155a0eff96 host: mn053-2hz1-01s43.uhc.com build_type: baseline_hp_checkfirmware ZTP Version: 3.12.2
2025-11-01 12:41:57,785 INFO   add_hostdata_loran() L44   pass: add payload to loran https://loran-core.optum.com/bmiapi/mn053-2hz1-01s43.uhc.com
2025-11-01 12:41:57,786 INFO   send_to_splunk() L14   fn:send_to_splunk: PROCESSING baseline_hp_checkfirmware build is processing at the moment see log
2025-11-01 12:41:57,829 INFO   add_status_event() L24   sending event to build_events topic for c18f50aa-223c-463e-a9e2-3f155a0eff96 with status PROCESSING
2025-11-01 12:41:57,931 ERROR  connect() L429  <BrokerConnection client_id=kafka-python-producer-1, node_id=0 host=localhost:9092 <connecting> [IPv6 ('::1', 9092, 0, 0)]>: Connect attempt returned error 111. Disconnecting.
2025-11-01 12:41:57,931 ERROR  connect() L429  <BrokerConnection client_id=kafka-python-producer-1, node_id=0 host=localhost:9092 <connecting> [IPv6 ('::1', 9092, 0, 0)]>: Connect attempt returned error 111. Disconnecting.
2025-11-01 12:41:57,931 ERROR  close() L945  <BrokerConnection client_id=kafka-python-producer-1, node_id=0 host=localhost:9092 <connecting> [IPv6 ('::1', 9092, 0, 0)]>: Closing connection. KafkaConnectionError: 111 ECONNREFUSED
2025-11-01 12:41:57,931 ERROR  close() L945  <BrokerConnection client_id=kafka-python-producer-1, node_id=0 host=localhost:9092 <connecting> [IPv6 ('::1', 9092, 0, 0)]>: Closing connection. KafkaConnectionError: 111 ECONNREFUSED
2025-11-01 12:41:58,047 INFO   update_loran_hostdata() L35   pass: update data to loran https://loran-core.optum.com/bmiapi/mn053-2hz1-01s43.uhc.com
2025-11-01 12:41:58,074 INFO   add_hostdata_loran() L44   pass: add payload to loran https://loran-core.optum.com/bmiapi/mn053-2hz1-01s43.uhc.com
2025-11-01 12:41:58,075 INFO   baseline_hp_checkfirmware() L89   Running checkfirmware for mn053-2hz1-01s43lo.uhc.com, deploy_firmware=True
2025-11-01 12:41:58,454 INFO   checkfirmware_service() L291  [mn053-2hz1-01s43lo.uhc.com] STEP 1: Checking node status
2025-11-01 12:41:59,601 INFO   ensure_node_removed() L106  [mn053-2hz1-01s43lo.uhc.com] Ensuring node is removed
2025-11-01 12:42:00,730 INFO   ensure_node_removed() L110  [mn053-2hz1-01s43lo.uhc.com] Node removed or not present
2025-11-01 12:42:00,730 INFO   add_node() L118  [mn053-2hz1-01s43lo.uhc.com] Adding node
2025-11-01 12:42:24,219 INFO   set_node_attributes() L132  [mn053-2hz1-01s43lo.uhc.com] Setting node attributes
2025-11-01 12:42:30,194 INFO   set_session_report_dir() L139  Setting session report_dir = /pub/reports/sum/mn053-2hz1-01s43lo.uhc.com/20251101_124158/reports
2025-11-01 12:42:30,935 INFO   run_inventory() L146  [mn053-2hz1-01s43lo.uhc.com] Running inventory
2025-11-01 12:55:00,238 INFO   wait_for_status() L90   [mn053-2hz1-01s43lo.uhc.com] Waiting for Inventory completion (max 30 min)
2025-11-01 12:55:01,086 INFO   wait_for_status() L95   [mn053-2hz1-01s43lo.uhc.com] Inventory complete after 1 min | Status: Update required
2025-11-01 12:55:01,086 INFO   generate_deploy_preview_report() L158  [mn053-2hz1-01s43lo.uhc.com] Generating deploy preview report
2025-11-01 12:55:04,986 ERROR  baseline_hp_checkfirmware() L96   Error running checkfirmware_service for mn053-2hz1-01s43lo.uhc.com: Command '['sudo', 'mv', '/pub/reports/sum/mn053-2hz1-01s43lo.uhc.com/20251101_124158/reports/SUM_Deploy_preview_Report_11-01-2025_12-55-01.csv', '/pub/reports/sum/mn053-2hz1-01s43lo.uhc.com/20251101_124158/reports/SUM_Deploy_preview_Report_11-01-2025_12-55-01.csv']' returned non-zero exit status 1.
2025-11-01 12:55:04,986 INFO   baseline_hp_checkfirmware() L98

 {
    "node": "mn053-2hz1-01s43lo.uhc.com",
    "status": "error",
    "message": "Command '['sudo', 'mv', '/pub/reports/sum/mn053-2hz1-01s43lo.uhc.com/20251101_124158/reports/SUM_Deploy_preview_Report_11-01-2025_12-55-01.csv', '/pub/reports/sum/mn053-2hz1-01s43lo.uhc.com/20251101_124158/reports/SUM_Deploy_preview_Report_11-01-2025_12-55-01.csv']' returned non-zero exit status 1.",
    "success": false
}


2025-11-01 12:55:05,037 INFO   update_loran_hostdata() L35   pass: update data to loran https://loran-core.optum.com/bmiapi/mn053-2hz1-01s43.uhc.com
2025-11-01 12:55:05,063 INFO   add_hostdata_loran() L44   pass: add payload to loran https://loran-core.optum.com/bmiapi/mn053-2hz1-01s43.uhc.com
2025-11-01 12:55:05,063 INFO   send_to_splunk() L14   fn:send_to_splunk: COMPLETE build completed successfully
2025-11-01 12:55:05,109 INFO   add_status_event() L24   sending event to build_events topic for c18f50aa-223c-463e-a9e2-3f155a0eff96 with status COMPLETE
2025-11-01 12:55:05,211 ERROR  connect() L429  <BrokerConnection client_id=kafka-python-producer-2, node_id=0 host=localhost:9092 <connecting> [IPv6 ('::1', 9092, 0, 0)]>: Connect attempt returned error 111. Disconnecting.
2025-11-01 12:55:05,211 ERROR  connect() L429  <BrokerConnection client_id=kafka-python-producer-2, node_id=0 host=localhost:9092 <connecting> [IPv6 ('::1', 9092, 0, 0)]>: Connect attempt returned error 111. Disconnecting.
2025-11-01 12:55:05,211 ERROR  close() L945  <BrokerConnection client_id=kafka-python-producer-2, node_id=0 host=localhost:9092 <connecting> [IPv6 ('::1', 9092, 0, 0)]>: Closing connection. KafkaConnectionError: 111 ECONNREFUSED
2025-11-01 12:55:05,211 ERROR  close() L945  <BrokerConnection client_id=kafka-python-producer-2, node_id=0 host=localhost:9092 <connecting> [IPv6 ('::1', 9092, 0, 0)]>: Closing connection. KafkaConnectionError: 111 ECONNREFUSED
2025-11-01 12:55:05,265 INFO   update_loran_hostdata() L35   pass: update data to loran https://loran-core.optum.com/bmiapi/mn053-2hz1-01s43.uhc.com
