#!/usr/bin/env python3

import argparse
import signal
import csv
import os
from datetime import datetime
from lib.xAppBase import xAppBase

# Global default directory for saving metrics
METRICS_DIR = "metrics"


class KpmStyle5Xapp(xAppBase):
    """
    xApp that subscribes to E2SM-KPM Report Service Style 5 and logs metrics in columnar CSV format.
    Each metric is a separate column, with a row per UE.
    """

    def __init__(
        self,
        config,
        http_server_port,
        rmr_port,
        metrics_dir,
        csv_filename="kpm_style5_metrics.csv",
    ):
        super(KpmStyle5Xapp, self).__init__(config, http_server_port, rmr_port)
        self.metrics_dir = metrics_dir
        self.metric_names = []  # Will be set in start()

        # Create metrics directory if needed
        if not os.path.exists(self.metrics_dir):
            try:
                os.makedirs(self.metrics_dir)
                print(f"✅ Created metrics directory: {self.metrics_dir}")
            except OSError as e:
                print(f"❌ Error creating directory {self.metrics_dir}: {e}")
                exit(1)

        self.csv_filepath = os.path.join(self.metrics_dir, csv_filename)

    def _write_csv_header(self, metric_names):
        """Write header to CSV with all metrics as column names."""
        if not os.path.exists(self.csv_filepath):
            try:
                with open(self.csv_filepath, mode="w", newline="") as csv_file:
                    writer = csv.writer(csv_file)
                    header = [
                        "Timestamp",
                        "E2AgentID",
                        "SubscriptionID",
                        "UE_ID",
                        "GranularityPeriod_ms",
                    ] + metric_names
                    writer.writerow(header)
                print(f"📄 Created and wrote header to {self.csv_filepath}")
            except IOError as e:
                print(f"❌ Error writing CSV header: {e}")
                exit(1)

    def subscription_callback(
        self, e2_agent_id, subscription_id, indication_hdr, indication_msg
    ):
        """
        Callback triggered when RIC Indication is received.
        Writes all metric values for each UE in a single row with metrics as columns.
        """
        print(
            f"\n📡 RIC Indication Received from {e2_agent_id} for Subscription ID: {subscription_id}"
        )
        timestamp = datetime.now().isoformat()

        # Extract data from E2 indication
        indication_hdr = self.e2sm_kpm.extract_hdr_info(indication_hdr)
        meas_data = self.e2sm_kpm.extract_meas_data(indication_msg)

        try:
            with open(self.csv_filepath, mode="a", newline="") as csv_file:
                writer = csv.writer(csv_file)
                for ue_id, ue_meas_data in meas_data.get("ueMeasData", {}).items():
                    granulPeriod = ue_meas_data.get("granulPeriod", "")
                    meas_values = ue_meas_data.get("measData", {})

                    row = [timestamp, e2_agent_id, subscription_id, ue_id, granulPeriod]
                    for metric in self.metric_names:
                        row.append(meas_values.get(metric, ""))  # default "" if missing

                    writer.writerow(row)
            print(f"✅ Metrics saved to {self.csv_filepath}")
        except Exception as e:
            print(f"❌ Error processing indication message: {e}")

    @xAppBase.start_function
    def start(self, e2_node_id, ue_ids, metric_names):
        """
        Entry point to start xApp subscription.
        """
        self.metric_names = metric_names
        self._write_csv_header(metric_names)

        report_period = 1000
        granul_period = 1000

        if len(ue_ids) < 2:
            dummy_ue_id = ue_ids[0] + 1 if ue_ids else 1
            ue_ids.append(dummy_ue_id)
            print(f"INFO: Added dummy UE ID for Style 5 requirement: {dummy_ue_id}")

        print(f"🔔 Subscribing to E2 node ID: {e2_node_id}")
        print(f"  - Report Style: 5")
        print(f"  - UE IDs: {ue_ids}")
        print(f"  - Metrics: {metric_names}")

        self.e2sm_kpm.subscribe_report_service_style_5(
            e2_node_id,
            report_period,
            ue_ids,
            metric_names,
            granul_period,
            self.subscription_callback,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KPM Style 5 xApp with CSV logging")
    parser.add_argument("--config", type=str, default="", help="xApp config file path")
    parser.add_argument(
        "--http_server_port", type=int, default=8092, help="HTTP server listen port"
    )
    parser.add_argument("--rmr_port", type=int, default=4562, help="RMR port")
    parser.add_argument(
        "--metrics_dir",
        type=str,
        default=METRICS_DIR,
        help="Directory to save the metrics CSV file",
    )
    parser.add_argument(
        "--e2_node_id", type=str, default="gnbd_001_001_00019b_0", help="E2 Node ID"
    )
    parser.add_argument("--ran_func_id", type=int, default=2, help="RAN function ID")
    parser.add_argument(
        "--ue_ids", type=str, default="0,1,2", help="Comma-separated list of UE IDs"
    )
    parser.add_argument(
        "--metrics",
        type=str,
        default="RRU.PrbAvailDl,RRU.PrbAvailUl,RRU.PrbUsedDl,RRU.PrbUsedUl,RACH.PreambleDedCell,DRB.UEThpDl,DRB.UEThpUl,DRB.RlcPacketDropRateDl,DRB.RlcSduTransmittedVolumeDL,DRB.RlcSduTransmittedVolumeUL,CQI,RSRP,RSRQ,DRB.RlcSduDelayDl,DRB.RlcDelayUl",
        help="Comma-separated list of metric names",
    )

    args = parser.parse_args()

    # Parse UE IDs and metric names
    ue_ids = list(map(int, args.ue_ids.split(",")))
    metric_names = args.metrics.split(",")

    # Create xApp
    kpmXapp = KpmStyle5Xapp(
        config=args.config,
        http_server_port=args.http_server_port,
        rmr_port=args.rmr_port,
        metrics_dir=args.metrics_dir,
    )
    kpmXapp.e2sm_kpm.set_ran_func_id(args.ran_func_id)

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGQUIT, kpmXapp.signal_handler)
    signal.signal(signal.SIGTERM, kpmXapp.signal_handler)
    signal.signal(signal.SIGINT, kpmXapp.signal_handler)

    # Start the xApp logic
    print("🚀 Starting KPM Style 5 xApp...")
    kpmXapp.start(args.e2_node_id, ue_ids, metric_names)
    print("✅ xApp started. Awaiting RIC indications...")
