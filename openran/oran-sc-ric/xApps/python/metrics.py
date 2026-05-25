#!/usr/bin/env python3

import argparse
import signal
import os
import csv
import time
from lib.xAppBase import xAppBase

METRICS_DIR = "metrics"
GNB_CSV_FILE = os.path.join(METRICS_DIR, "gnb_metrics.csv")
UE_CSV_FILE = os.path.join(METRICS_DIR, "ue_metrics.csv")


class MetricsCollectorXapp(xAppBase):
    def __init__(self, config, http_server_port, rmr_port):
        super(MetricsCollectorXapp, self).__init__(config, http_server_port, rmr_port)

        # Hardcoded metric lists
        self.gnb_metrics = [
            "RRU.PrbAvailDl",
            "RRU.PrbAvailUl",
            "RRU.PrbUsedDl",
            "RRU.PrbUsedUl",
            "RACH.PreambleDedCell",
        ]
        self.ue_metrics = [
            "DRB.UEThpDl",
            "DRB.UEThpUl",
            "DRB.RlcPacketDropRateDl",
            "DRB.RlcSduTransmittedVolumeDL",
            "DRB.RlcSduTransmittedVolumeUL",
            "CQI",
            "RSRP",
            "RSRQ",
            "DRB.RlcSduDelayDl",
            "DRB.RlcDelayUl",
        ]

        self.gnb_headers = [
            "timestamp",
            "report_type",
            "e2_agent_id",
            "subscription_id",
            "ue_id",
            "granularity_period",
        ] + self.gnb_metrics
        self.ue_headers = [
            "timestamp",
            "report_type",
            "e2_agent_id",
            "subscription_id",
            "ue_id",
            "granularity_period",
        ] + self.ue_metrics

        self._setup_storage()

    def _setup_storage(self):
        print(f"INFO: Ensuring metrics directory exists at './{METRICS_DIR}'")
        os.makedirs(METRICS_DIR, exist_ok=True)
        # Prepare GNB CSV file with headers
        if not os.path.exists(GNB_CSV_FILE):
            with open(GNB_CSV_FILE, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=self.gnb_headers)
                writer.writeheader()
        # Prepare UE CSV file with headers
        if not os.path.exists(UE_CSV_FILE):
            with open(UE_CSV_FILE, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=self.ue_headers)
                writer.writeheader()

    def _write_to_csv(self, filename, headers, data_dict):
        try:
            if not os.path.exists(filename):
                with open(filename, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=headers)
                    writer.writeheader()
            with open(filename, "a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                # Filter data_dict to include only keys in headers
                filtered_data = {k: data_dict.get(k, "") for k in headers}
                writer.writerow(filtered_data)
        except Exception as e:
            print(f"ERROR: Could not write to CSV file {filename}: {e}")

    def _write_to_csv_dynamic(self, filename, new_headers, row_data):
        try:
            file_exists = os.path.exists(filename)

            # Get existing headers if file exists
            if file_exists:
                with open(filename, "r", newline="") as f:
                    reader = csv.reader(f)
                    existing_headers = next(reader)
            else:
                existing_headers = []

            # Merge existing and new headers
            all_headers = list(dict.fromkeys(existing_headers + new_headers))

            # Load previous rows if needed
            rows = []
            if file_exists:
                with open(filename, "r", newline="") as f:
                    reader = csv.DictReader(f)
                    rows = list(reader)

            # Append new row
            rows.append(row_data)

            # Write everything back with updated headers
            with open(filename, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=all_headers)
                writer.writeheader()
                for row in rows:
                    writer.writerow({h: row.get(h, "") for h in all_headers})
        except Exception as e:
            print(f"ERROR: Could not write to CSV file {filename}: {e}")

    def gnb_indication_callback(
        self, e2_agent_id, subscription_id, indication_hdr, indication_msg
    ):
        print(f"\n✅ Received gNB Indication from {e2_agent_id}")

        header_info = self.e2sm_kpm.extract_hdr_info(indication_hdr)
        meas_data = self.e2sm_kpm.extract_meas_data(indication_msg)

        row_data = {
            "timestamp": header_info["colletStartTime"],
            "report_type": "GNB",
            "e2_agent_id": e2_agent_id,
            "subscription_id": subscription_id,
            "ue_id": "",  # No UE ID for gNB
            "granularity_period": meas_data.get("granulPeriod", None),
        }
        # Add only gNB metrics if present
        for metric in self.gnb_metrics:
            row_data[metric] = meas_data.get("measData", {}).get(metric, "")

        self._write_to_csv(GNB_CSV_FILE, self.gnb_headers, row_data)
        print(f"   -> GNB data stored in {GNB_CSV_FILE}")

    # def ue_indication_callback(self, e2_agent_id, subscription_id, indication_hdr, indication_msg):
    #     print(f"\n✅ Received UE Indication from {e2_agent_id}")

    #     header_info = self.e2sm_kpm.extract_hdr_info(indication_hdr)
    #     meas_data = self.e2sm_kpm.extract_meas_data(indication_msg)

    #     for ue_id, ue_meas_data in meas_data.get("ueMeasData", {}).items():
    #         row_data = {
    #             'timestamp': header_info['colletStartTime'],
    #             'report_type': 'UE',
    #             'e2_agent_id': e2_agent_id,
    #             'subscription_id': subscription_id,
    #             'ue_id': ue_id,
    #             'granularity_period': ue_meas_data.get("granulPeriod", None)
    #         }
    #         # Add only UE metrics if present
    #         for metric in self.ue_metrics:
    #             row_data[metric] = ue_meas_data.get("measData", {}).get(metric, '')

    #         # self._write_to_csv(UE_CSV_FILE, self.ue_headers, row_data)
    #         per_ue_file = os.path.join(METRICS_DIR, f"{ue_id}_metrics.csv")
    #         self._write_to_csv(per_ue_file, self.ue_headers, row_data)

    #     print(f"   -> UE data for {len(meas_data.get('ueMeasData', {}))} UEs stored in {UE_CSV_FILE}")
    def ue_indication_callback(
        self, e2_agent_id, subscription_id, indication_hdr, indication_msg
    ):
        print(f"\n✅ Received UE Indication from {e2_agent_id}")

        header_info = self.e2sm_kpm.extract_hdr_info(indication_hdr)
        meas_data = self.e2sm_kpm.extract_meas_data(indication_msg)
        ue_meas_data_dict = meas_data.get("ueMeasData", {})

        for ue_id, ue_meas_data in ue_meas_data_dict.items():
            all_metrics = ue_meas_data.get("measData", {})

            # Construct row with base info
            row_data = {
                "timestamp": header_info.get("colletStartTime", ""),
                "report_type": "UE",
                "e2_agent_id": e2_agent_id,
                "subscription_id": subscription_id,
                "ue_id": ue_id,
                "granularity_period": ue_meas_data.get("granulPeriod", None),
            }

            # Append dynamic metrics
            row_data.update(all_metrics)

            # Compute full dynamic header
            dynamic_headers = list(row_data.keys())

            # Write to combined UE CSV
            self._write_to_csv_dynamic(UE_CSV_FILE, dynamic_headers, row_data)

            # Write to per-UE CSV
            per_ue_file = os.path.join(METRICS_DIR, f"{ue_id}_metrics.csv")
            self._write_to_csv_dynamic(per_ue_file, dynamic_headers, row_data)

        print(
            f"   -> Stored UE metrics for {len(ue_meas_data_dict)} UEs (combined and per-UE files)."
        )

    def _subscribe_with_retry(
        self, subscription_func, description, *args, max_retries=5, initial_delay=5
    ):
        for attempt in range(max_retries):
            try:
                print(f"INFO: {description} (attempt {attempt + 1}/{max_retries})")
                subscription_func(*args)
                print(f"SUCCESS: {description} succeeded")
                return True
            except Exception as e:
                error_msg = str(e)
                print(
                    f"ERROR: {description} failed on attempt {attempt + 1}: {error_msg}"
                )

                if "503" in error_msg or "Service Unavailable" in error_msg:
                    if attempt < max_retries - 1:
                        delay = initial_delay * (2**attempt)
                        print(
                            f"INFO: Service unavailable, retrying in {delay} seconds..."
                        )
                        time.sleep(delay)
                        continue
                    else:
                        print(
                            f"ERROR: {description} failed after {max_retries} attempts due to service unavailability"
                        )
                        return False
                elif "json" in error_msg.lower() or "decode" in error_msg.lower():
                    if attempt < max_retries - 1:
                        delay = initial_delay * (2**attempt)
                        print(
                            f"INFO: Subscription response error, retrying in {delay} seconds..."
                        )
                        time.sleep(delay)
                        continue
                    else:
                        print(
                            f"ERROR: {description} failed after {max_retries} attempts due to response errors"
                        )
                        return False
                else:
                    print(
                        f"ERROR: {description} failed with non-recoverable error: {error_msg}"
                    )
                    return False
        return False

    @xAppBase.start_function
    def start(self, e2_node_id):
        report_period = 1000
        granul_period = 1000

        print(f"INFO: Starting Metrics Collector xApp for E2 Node: {e2_node_id}")

        # Subscribe to gNB metrics (Style 1)
        gnb_success = self._subscribe_with_retry(
            self.e2sm_kpm.subscribe_report_service_style_1,
            "Subscribing to gNB metrics (Style 1)",
            e2_node_id,
            report_period,
            self.gnb_metrics,
            granul_period,
            self.gnb_indication_callback,
        )

        ue_ids = [0, 1, 2]  # <-- Replace with actual UE IDs if known
        ue_success_list = []

        for ue_id in ue_ids:
            success = self._subscribe_with_retry(
                self.e2sm_kpm.subscribe_report_service_style_2,
                f"Subscribing to UE metrics for UE {ue_id} (Style 2)",
                e2_node_id,
                report_period,
                ue_id,
                self.ue_metrics,
                granul_period,
                self.ue_indication_callback,
            )
        ue_success_list.append(success)

        if gnb_success and all(ue_success_list):
            print("SUCCESS: All subscriptions completed successfully")
        elif gnb_success or any(ue_success_list):
            print(
                "WARNING: Some subscriptions failed, but continuing with partial functionality"
            )
        else:
            print("ERROR: All subscriptions failed, but xApp will continue running")

        print("INFO: xApp is running and will process subscriptions...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Metrics Collector xApp")
    parser.add_argument("--config", type=str, default="", help="xApp config file path")
    parser.add_argument(
        "--http_server_port", type=int, default=8092, help="HTTP server listen port"
    )
    parser.add_argument("--rmr_port", type=int, default=4562, help="RMR port")
    parser.add_argument(
        "--e2_node_id",
        type=str,
        default="gnbd_001_001_00019b_0",
        help="Target E2 Node ID",
    )
    parser.add_argument(
        "--ran_func_id", type=int, default=2, help="E2SM-KPM RAN function ID"
    )

    args = parser.parse_args()

    metrics_xapp = MetricsCollectorXapp(
        args.config, args.http_server_port, args.rmr_port
    )
    metrics_xapp.e2sm_kpm.set_ran_func_id(args.ran_func_id)

    signal.signal(signal.SIGQUIT, metrics_xapp.signal_handler)
    signal.signal(signal.SIGTERM, metrics_xapp.signal_handler)
    signal.signal(signal.SIGINT, metrics_xapp.signal_handler)

    metrics_xapp.start(args.e2_node_id)
