#!/usr/bin/env python3

import argparse
import signal
import os
import csv
import time
import json
from lib.xAppBase import xAppBase

# MODIFIED: Define a single file for combined data
METRICS_DIR = "metrics"
COMBINED_CSV_FILE = os.path.join(METRICS_DIR, "combined_data.csv")


class MetricsCollectorXapp(xAppBase):
    # MODIFIED: Pass headers during initialization
    def __init__(self, config, http_server_port, rmr_port, csv_headers):
        super(MetricsCollectorXapp, self).__init__(config, http_server_port, rmr_port)
        self.csv_headers = csv_headers
        self.headers_written = False
        self._setup_storage()

    def _setup_storage(self):
        """Creates the metrics directory and prepares the CSV file."""
        print(f"INFO: Ensuring metrics directory exists at './{METRICS_DIR}'")
        os.makedirs(METRICS_DIR, exist_ok=True)
        # Create or clear the file and write headers immediately if they don't exist
        if not os.path.exists(COMBINED_CSV_FILE):
             with open(COMBINED_CSV_FILE, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.csv_headers)
                writer.writeheader()
                self.headers_written = True

    # MODIFIED: Combined callback logic for writing to a single file
    def _write_to_csv(self, data_dict):
        """Appends a dictionary of data as a new row in the combined CSV file."""
        try:
            with open(COMBINED_CSV_FILE, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.csv_headers)
                # Write header only if the file was just created
                if not self.headers_written:
                    writer.writeheader()
                    self.headers_written = True
                writer.writerow(data_dict)
        except Exception as e:
            print(f"ERROR: Could not write to CSV file: {e}")

    def gnb_indication_callback(self, e2_agent_id, subscription_id, indication_hdr, indication_msg):
        """Processes and stores cell-level (gNB) metrics."""
        print(f"\n✅ Received gNB Indication from {e2_agent_id}")
        
        header_info = self.e2sm_kpm.extract_hdr_info(indication_hdr)
        meas_data = self.e2sm_kpm.extract_meas_data(indication_msg)

        row_data = {
            'timestamp': header_info['colletStartTime'],
            'report_type': 'GNB',
            'e2_agent_id': e2_agent_id,
            'subscription_id': subscription_id,
            'ue_id': '',  # No UE ID for GNB reports
            'granularity_period': meas_data.get("granulPeriod")
        }
        # Add all measurement data to the row
        row_data.update(meas_data.get("measData", {}))
        
        self._write_to_csv(row_data)
        print(f"   -> GNB data stored in {COMBINED_CSV_FILE}")

    def ue_indication_callback(self, e2_agent_id, subscription_id, indication_hdr, indication_msg):
        """Processes and stores UE-level metrics."""
        print(f"\n✅ Received UE Indication from {e2_agent_id}")
        
        header_info = self.e2sm_kpm.extract_hdr_info(indication_hdr)
        meas_data = self.e2sm_kpm.extract_meas_data(indication_msg)

        # Iterate through each UE in the report
        for ue_id, ue_meas_data in meas_data.get("ueMeasData", {}).items():
            row_data = {
                'timestamp': header_info['colletStartTime'],
                'report_type': 'UE',
                'e2_agent_id': e2_agent_id,
                'subscription_id': subscription_id,
                'ue_id': ue_id,
                'granularity_period': ue_meas_data.get("granulPeriod")
            }
            # Add all measurement data for this UE to the row
            row_data.update(ue_meas_data.get("measData", {}))
            
            self._write_to_csv(row_data)
        
        print(f"   -> UE data for {len(meas_data.get('ueMeasData', {}))} UEs stored in {COMBINED_CSV_FILE}")

    def _subscribe_with_retry(self, subscription_func, description, *args, max_retries=5, initial_delay=5):
        """Helper method to retry subscriptions with exponential backoff."""
        for attempt in range(max_retries):
            try:
                print(f"INFO: {description} (attempt {attempt + 1}/{max_retries})")
                subscription_func(*args)
                print(f"SUCCESS: {description} succeeded")
                return True
            except Exception as e:
                error_msg = str(e)
                print(f"ERROR: {description} failed on attempt {attempt + 1}: {error_msg}")
                
                # Check if it's a 503 service unavailable error
                if "503" in error_msg or "Service Unavailable" in error_msg:
                    if attempt < max_retries - 1:
                        delay = initial_delay * (2 ** attempt)  # Exponential backoff
                        print(f"INFO: Service unavailable, retrying in {delay} seconds...")
                        time.sleep(delay)
                        continue
                    else:
                        print(f"ERROR: {description} failed after {max_retries} attempts due to service unavailability")
                        return False
                elif "json" in error_msg.lower() or "decode" in error_msg.lower():
                    # JSON decode error likely means subscription service returned error response
                    if attempt < max_retries - 1:
                        delay = initial_delay * (2 ** attempt)
                        print(f"INFO: Subscription response error, retrying in {delay} seconds...")
                        time.sleep(delay)
                        continue
                    else:
                        print(f"ERROR: {description} failed after {max_retries} attempts due to response errors")
                        return False
                else:
                    # Other errors, fail immediately
                    print(f"ERROR: {description} failed with non-recoverable error: {error_msg}")
                    return False
        return False

    @xAppBase.start_function
    def start(self, e2_node_id, metrics_to_request):
        """Starts the xApp by creating two subscriptions with retry logic."""
        report_period = 1000
        granul_period = 1000
        
        print(f"INFO: Starting Metrics Collector xApp for E2 Node: {e2_node_id}")
        print(f"INFO: Requested metrics: {metrics_to_request}")
        
        # Subscribe to gNB metrics with retry
        gnb_success = self._subscribe_with_retry(
            self.e2sm_kpm.subscribe_report_service_style_1,
            "Subscribing to gNB metrics (Style 1)",
            e2_node_id, report_period, metrics_to_request, granul_period, self.gnb_indication_callback
        )
        
        # Subscribe to UE metrics with retry (Style 3 only supports 1 metric at a time)
        matching_conds = [{'matchingCondChoice': ('testCondInfo', {'testType': ('ul-rSRP', 'true'), 'testExpr': 'lessthan', 'testValue': ('valueInt', 1000)})}]
        primary_ue_metric = [metrics_to_request[0]] if metrics_to_request else ['DRB.UEThpDl']
        print(f"INFO: Style 3 supports only 1 metric - using: {primary_ue_metric[0]}")
        
        ue_success = self._subscribe_with_retry(
            self.e2sm_kpm.subscribe_report_service_style_3,
            "Subscribing to UE metrics (Style 3)",
            e2_node_id, report_period, matching_conds, primary_ue_metric, granul_period, self.ue_indication_callback
        )
        
        # Report subscription status
        if gnb_success and ue_success:
            print("SUCCESS: All subscriptions completed successfully")
        elif gnb_success or ue_success:
            print("WARNING: Some subscriptions failed, but continuing with partial functionality")
        else:
            print("ERROR: All subscriptions failed, but xApp will continue running to retry or handle future requests")
            
        # Keep the xApp running regardless of initial subscription failures
        print("INFO: xApp is now running and will continue to process any successful subscriptions...")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Metrics Collector xApp')
    parser.add_argument("--config", type=str, default='', help="xApp config file path")
    parser.add_argument("--http_server_port", type=int, default=8092, help="HTTP server listen port")
    parser.add_argument("--rmr_port", type=int, default=4562, help="RMR port")
    parser.add_argument("--e2_node_id", type=str, default='gnbd_001_001_00019b_0', help="Target E2 Node ID")
    parser.add_argument("--ran_func_id", type=int, default=2, help="E2SM-KPM RAN function ID")
    parser.add_argument("--metrics", type=str, default='DRB.UEThpUl,DRB.UEThpDl,DRB.RlcPacketDropRateDl,DRB.PacketSuccessRateUlgNBUu,DRB.RlcSduTransmittedVolumeDL,DRB.RlcSduTransmittedVolumeUL', help="Comma-separated KPM metrics")

    args = parser.parse_args()
    metrics = args.metrics.split(",")
    
    # MODIFIED: Define the complete set of headers for the CSV file
    csv_headers = ['timestamp', 'report_type', 'e2_agent_id', 'subscription_id', 'ue_id', 'granularity_period'] + metrics

    # MODIFIED: Pass headers to the xApp constructor
    metrics_xapp = MetricsCollectorXapp(args.config, args.http_server_port, args.rmr_port, csv_headers)
    metrics_xapp.e2sm_kpm.set_ran_func_id(args.ran_func_id)

    signal.signal(signal.SIGQUIT, metrics_xapp.signal_handler)
    signal.signal(signal.SIGTERM, metrics_xapp.signal_handler)
    signal.signal(signal.SIGINT, metrics_xapp.signal_handler)

    metrics_xapp.start(args.e2_node_id, metrics)