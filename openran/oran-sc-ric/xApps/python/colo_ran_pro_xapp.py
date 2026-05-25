#!/usr/bin/env python3

import argparse
import signal
import threading
import time
import csv
import os
from lib.xAppBase import xAppBase

# Define the metrics to be collected. These are based on the user's request.
# Note: Availability of these metrics depends on the E2 Agent implementation.

# Metrics to be collected at the gNB/E2-Node level
GNB_METRICS = [
    "RRU.PrbTotDl",         # Used as a proxy for DL bitrate/load
    "RRU.PrbTotUl",         # Used as a proxy for UL bitrate/load
    "RRU.ULInterferenceAvg",# Average UL Interference - potential jamming indicator
    "Handover.Attempt",     # Number of handover attempts
    "Handover.Success",     # Number of successful handovers
    "RRC.ConnEstabAttempt", # Number of RRC connection establishment attempts
    "RRC.ConnEstabSuccess", # Number of successful RRC connections
    "RRC.ConnReEstabAttempt", # Number of RRC connection re-establishment attempts
    "RRC.ConnReEstabSuccess", # Number of successful RRC connection re-establishments
]

# Metrics to be collected at the UE level
UE_METRICS = [
    # Throughput and Volume
    "DRB.UEThpDl",          # Downlink Throughput
    "DRB.UEThpUl",          # Uplink Throughput
    "DRB.RlcSduTransmittedVolumeDL", # Downlink Data Volume
    "DRB.RlcSduReceiveVolumeUL",   # Uplink Data Volume
    # Radio Link Quality
    "Radio.RSRP",           # Reference Signal Received Power
    "Radio.RSRQ",           # Reference Signal Received Quality
    "Radio.SINR",           # Signal to Interference and Noise Ratio
    "Radio.CQI",            # Channel Quality Indicator
    "Radio.MCS",            # Modulation and Coding Scheme
    # Latency and Reliability
    "DRB.PdcpSduDelayDl",   # DL PDCP SDU Delay
    "MAC.HarqNackRateUl",   # UL HARQ NACK Rate
    "MAC.HarqNackRateDl",   # DL HARQ NACK Rate
    # QoS
    "QoS.FiveQI",           # 5G QoS Identifier
    "QoS.ARP",              # Allocation and Retention Priority
    # Potential Security/Anomaly Indicators
    "Radio.ULInterference", # Uplink Interference - potential jamming/misbehavior
    "DRB.PdcpPduDiscDl",    # DL PDCP PDU Discard Rate - potential traffic flood
    "DRB.PdcpPduDiscUl",    # UL PDCP PDU Discard Rate - potential compromised UE
    "Radio.TxPower",        # UE Transmission Power - potential DoS indicator
    "Radio.TimingAdvance",  # UE Timing Advance - can indicate movement or spoofing
    "PDCP.IntegrityFailure",# PDCP Integrity Protection Failures - strong attack indicator
    "RRC.ConnRelAbnormal",  # Abnormal RRC Connection Release
]

# CSV file headers
GNB_CSV_HEADER = ['timestamp', 'e2_node_id', 'num_ues', 'dl_prb_usage', 'ul_prb_usage', 'ul_interference_avg', 'ho_attempt', 'ho_success', 'rrc_conn_attempt', 'rrc_conn_success', 'rrc_conn_re_estab_attempt', 'rrc_conn_re_estab_success']
UE_CSV_HEADER = [
    'timestamp', 'e2_node_id', 'ue_id', 'dl_throughput_mbps', 'ul_throughput_mbps', 
    'dl_volume_kb', 'ul_volume_kb', 'rsrp', 'rsrq', 'sinr', 'cqi', 'mcs',
    'pdcp_delay_dl', 'harq_nack_ul', 'harq_nack_dl', 'five_qi', 'arp', 'ul_interference', 
    'pdcp_pdu_disc_dl', 'pdcp_pdu_disc_ul', 'tx_power', 'timing_advance', 
    'pdcp_integrity_failure', 'rrc_conn_rel_abnormal'
]

class ColoRanProXapp(xAppBase):
    def __init__(self, config, http_server_port, rmr_port, log_interval):
        super(ColoRanProXapp, self).__init__(config, http_server_port, rmr_port)
        self.log_interval = log_interval
        
        # In-memory storage for metrics
        self.gnb_state = {}
        self.ue_state = {}
        
        # Thread for periodic logging
        self.log_thread = threading.Thread(target=self.log_data_loop)
        self.log_thread.daemon = True

        # Create metrics directory if it doesn't exist
        if not os.path.exists('metrics'):
            os.makedirs('metrics')

        # Initialize CSV files
        self._initialize_csv('metrics/gnb_metrics.csv', GNB_CSV_HEADER)
        self._initialize_csv('metrics/ue_metrics.csv', UE_CSV_HEADER)

    def _initialize_csv(self, filename, header):
        if not os.path.exists(filename):
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(header)

    def gnb_subscription_callback(self, e2_agent_id, subscription_id, indication_hdr, indication_msg):
        """Callback for gNB-level metrics from Style 1 subscription."""
        current_time = time.time()
        self.gnb_state.setdefault(e2_agent_id, {'timestamp': current_time})

        meas_data = self.e2sm_kpm.extract_meas_data(indication_msg)
        for metric_name, value in meas_data.get("measData", {}).items():
            self.gnb_state[e2_agent_id][metric_name] = value[0] if isinstance(value, list) else value

    def ue_subscription_callback(self, e2_agent_id, subscription_id, indication_hdr, indication_msg):
        """Callback for UE-level metrics from Style 4 subscription."""
        current_time = time.time()
        meas_data = self.e2sm_kpm.extract_meas_data(indication_msg)

        # Update number of UEs for the gNB state
        self.gnb_state.setdefault(e2_agent_id, {})['num_ues'] = len(meas_data.get("ueMeasData", {}))

        for ue_id, ue_meas_data in meas_data.get("ueMeasData", {}).items():
            self.ue_state.setdefault(e2_agent_id, {}).setdefault(ue_id, {'timestamp': current_time})
            self.ue_state[e2_agent_id][ue_id]['timestamp'] = current_time
            for metric_name, value in ue_meas_data.get("measData", {}).items():
                # Take the first value if it's a list
                self.ue_state[e2_agent_id][ue_id][metric_name] = value[0] if isinstance(value, list) else value

    def log_data_loop(self):
        """Periodically writes the collected data to CSV files."""
        while self.running:
            time.sleep(self.log_interval)
            
            # Log gNB data
            with open('metrics/gnb_metrics.csv', 'a', newline='') as f:
                writer = csv.writer(f)
                if f.tell() == 0: # Write header if file is empty
                    writer.writerow(GNB_CSV_HEADER)
                for node_id, data in self.gnb_state.items():
                    writer.writerow([
                        data.get('timestamp', ''),
                        node_id,
                        data.get('num_ues', 0),
                        data.get('RRU.PrbTotDl', 'N/A'),
                        data.get('RRU.PrbTotUl', 'N/A'),
                        data.get('RRU.ULInterferenceAvg', 'N/A'),
                        data.get('Handover.Attempt', 'N/A'),
                        data.get('Handover.Success', 'N/A'),
                        data.get('RRC.ConnEstabAttempt', 'N/A'),
                        data.get('RRC.ConnEstabSuccess', 'N/A'),
                        data.get('RRC.ConnReEstabAttempt', 'N/A'),
                        data.get('RRC.ConnReEstabSuccess', 'N/A')
                    ])

            # Log UE data to both combined and separate files
            with open('metrics/ue_metrics.csv', 'a', newline='') as combined_f:
                combined_writer = csv.writer(combined_f)
                if combined_f.tell() == 0: # Write header if file is empty
                    combined_writer.writerow(UE_CSV_HEADER)

                for node_id, ues in self.ue_state.items():
                    for ue_id, data in ues.items():
                        row_data = [
                            data.get('timestamp', ''),
                            node_id,
                            ue_id,
                            data.get('DRB.UEThpDl', 'N/A'),
                            data.get('DRB.UEThpUl', 'N/A'),
                            data.get('DRB.RlcSduTransmittedVolumeDL', 'N/A'),
                            data.get('DRB.RlcSduReceiveVolumeUL', 'N/A'),
                            data.get('Radio.RSRP', 'N/A'),
                            data.get('Radio.RSRQ', 'N/A'),
                            data.get('Radio.SINR', 'N/A'),
                            data.get('Radio.CQI', 'N/A'),
                            data.get('Radio.MCS', 'N/A'),
                            data.get('DRB.PdcpSduDelayDl', 'N/A'),
                            data.get('MAC.HarqNackRateUl', 'N/A'),
                            data.get('MAC.HarqNackRateDl', 'N/A'),
                            data.get('QoS.FiveQI', 'N/A'),
                            data.get('QoS.ARP', 'N/A'),
                            data.get('Radio.ULInterference', 'N/A'),
                            data.get('DRB.PdcpPduDiscDl', 'N/A'),
                            data.get('DRB.PdcpPduDiscUl', 'N/A'),
                            data.get('Radio.TxPower', 'N/A'),
                            data.get('Radio.TimingAdvance', 'N/A'),
                            data.get('PDCP.IntegrityFailure', 'N/A'),
                            data.get('RRC.ConnRelAbnormal', 'N/A')
                        ]
                        
                        # Write to the combined UE metrics file
                        combined_writer.writerow(row_data)

                        # Write to a separate file for each UE
                        ue_filename = f"metrics/ue_{ue_id}_metrics.csv"
                        file_exists = os.path.exists(ue_filename)
                        with open(ue_filename, 'a', newline='') as separate_f:
                            separate_writer = csv.writer(separate_f)
                            if not file_exists:
                                separate_writer.writerow(UE_CSV_HEADER)
                            separate_writer.writerow(row_data)

            if self.ue_state:
                print(f"[{time.ctime()}] Logged metrics to gnb_metrics.csv, ue_metrics.csv, and individual UE files.")
            else:
                print(f"[{time.ctime()}] Logged metrics to gnb_metrics.csv. No UE metrics to log.")


    @xAppBase.start_function
    def start(self, e2_node_id):
        """Main xApp function to set up subscriptions and start logging."""
        report_period = 1000  # ms
        granul_period = 1000  # ms

        # --- Subscription for gNB-level metrics ---
        print(f"Subscribing to gNB-level metrics for E2 node ID: {e2_node_id}")
        self.e2sm_kpm.subscribe_report_service_style_1(
            e2_node_id, report_period, GNB_METRICS, granul_period, self.gnb_subscription_callback
        )

        # --- Subscription for UE-level metrics ---
        # Use a dummy condition that is always true to capture all UEs
        matchingUeConds = [{'testCondInfo': {'testType': ('ul-rSRP', 'true'), 'testExpr': 'lessthan', 'testValue': ('valueInt', 1000)}}]
        print(f"Subscribing to UE-level metrics for E2 node ID: {e2_node_id}")
        self.e2sm_kpm.subscribe_report_service_style_4(
            e2_node_id, report_period, matchingUeConds, UE_METRICS, granul_period, self.ue_subscription_callback
        )

        # Start the logging thread
        self.log_thread.start()
        print("xApp started. Logging metrics every {} seconds.".format(self.log_interval))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Professional KPM Monitoring xApp for Colo-RAN style data collection')
    parser.add_argument("--config", type=str, default='', help="xApp config file path")
    parser.add_argument("--http_server_port", type=int, default=8092, help="HTTP server listen port")
    parser.add_argument("--rmr_port", type=int, default=4562, help="RMR port")
    parser.add_argument("--e2_node_id", type=str, default='gnbd_001_001_00019b_0', help="E2 Node ID to subscribe to")
    parser.add_argument("--ran_func_id", type=int, default=2, help="E2SM-KPM RAN function ID")
    parser.add_argument("--log_interval", type=int, default=10, help="Interval in seconds to log data to CSV")

    args = parser.parse_args()
    
    myXapp = ColoRanProXapp(args.config, args.http_server_port, args.rmr_port, args.log_interval)
    myXapp.e2sm_kpm.set_ran_func_id(args.ran_func_id)

    signal.signal(signal.SIGQUIT, myXapp.signal_handler)
    signal.signal(signal.SIGTERM, myXapp.signal_handler)
    signal.signal(signal.SIGINT, myXapp.signal_handler)

    myXapp.start(args.e2_node_id)
