#!/usr/bin/env python3

import argparse
import signal
import joblib
from datetime import datetime
from lib.xAppBase import xAppBase
from lib.ml_models import CNN_GRU,CNN_LSTM
import pandas as pd
import numpy as np
import torch
import torch.nn as nn


class KpmStyle5Xapp(xAppBase):
    """
    xApp that subscribes to E2SM-KPM Report Service Style 5, performs feature engineering,
    and uses a pre-trained model to predict malicious UEs.
    """
    def __init__(self, config, http_server_port, rmr_port, s1_model_path, s2_ben_path, s2_mal_path, buffer_size=100):
        super(KpmStyle5Xapp, self).__init__(config, http_server_port, rmr_port)
        self.metric_names = []
        self.data_buffer = []
        self.buffer_size = buffer_size
        # self.model = None
        self.selected_features = None
        self.s1_model = None
        self.s2_ben_model = None
        self.s2_mal_model = None
        self.le_malicious = [
            "parallel_tcp_flood",
            "udp_fragmentation_flood",
            "udp_flood",
            "small_packet_flood",
            "pulsing_udp_flood",
            "parallel_udp_flood",
            "parallel_tcp_flood"
        ]
        self.le_benign = [
            "embb",
            "mtc",
            "urllc",
            "voip"
        ]
        self._orig_restore_location = torch.serialization.default_restore_location

        # Define a plain function, not a method
        def cpu_unpickler(storage, location, *args, **kwargs):
            return self._orig_restore_location(storage, "cpu")

        # Override the restore function globally
        torch.serialization.default_restore_location = cpu_unpickler

        # Load the pre-trained model
        try:
            # Load Stage 1 model (binary classification)
            self.s1_model, self.s1_features = joblib.load(s1_model_path, mmap_mode=None)

            # Load Stage 2 benign model
            self.s2_ben_model, self.s2_ben_features = joblib.load(s2_ben_path, mmap_mode=None)

            # Load Stage 2 malicious model
            self.s2_mal_model, self.s2_mal_features = joblib.load(s2_mal_path, mmap_mode=None)

            print(f"✅ Models loaded successfully:")
            print(f"   - Stage 1: {s1_model_path}")
            print(f"   - Stage 2 (Benign): {s2_ben_path}")
            print(f"   - Stage 2 (Malicious): {s2_mal_path}")

        except FileNotFoundError as fnf_error:
            print(f"❌ WARNING: Model file not found: {fnf_error.filename}. The 'predict' function will not work.")
        except Exception as e:
            print(f"❌ ERROR: Unexpected error while loading models: {e}. The 'predict' function will not work.")

    def _extract_value(self, value):
        """Helper function to extract numeric values from various formats."""
        try:
            if isinstance(value, list):
                return float(value[0]) if value else 0.0
            elif value is None:
                return 0.0
            else:
                return float(value)
        except (ValueError, TypeError):
            return 0.0

    def _feature_engineer_network_data(self, cleaned_dataset):
        """
        Performs feature engineering on a network dataset to create a set of
        pre-defined features for machine learning.
        """
        df = cleaned_dataset.copy()
        # df["Timestamp"] = pd.to_datetime(df["Timestamp"])
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')  # convert to datetime
        # df['Timestamp_epoch'] = df['Timestamp'].astype('int64') // 10**9
        df = df.sort_values(by=["E2AgentID", "UE_ID", "Timestamp"])
        epsilon = 1e-5

        # This block is now technically redundant but acts as a good safeguard.
        for col in self.metric_names:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        df.fillna(0, inplace=True)

        new_features = {}
        new_features["PRB_Utilization_Ratio_DL"] = df["RRU.PrbUsedDl"] / (df["RRU.PrbAvailDl"] + epsilon)
        new_features["PRB_Utilization_Ratio_UL"] = df["RRU.PrbUsedUl"] / (df["RRU.PrbAvailUl"] + epsilon)
        new_features["UL_PRB_Efficiency"] = df["DRB.UEThpUl"] / (df["RRU.PrbUsedUl"] + epsilon)
        new_features["DL_PRB_Efficiency"] = df["DRB.UEThpDl"] / (df["RRU.PrbUsedDl"] + epsilon)
        new_features["Resource_Imbalance"] = abs(new_features["PRB_Utilization_Ratio_DL"] - new_features["PRB_Utilization_Ratio_UL"])
        new_features["Signal_Quality_Index"] = (df["RSRP"] + df["RSRQ"] + df["CQI"]) / 3
        new_features["Throughput_Asymmetry"] = df["DRB.UEThpDl"] / (df["DRB.UEThpUl"] + epsilon)
        new_features["UL_Throughput_per_Volume"] = df["DRB.UEThpUl"] / (df["DRB.RlcSduTransmittedVolumeUL"] + epsilon)
        new_features["DL_Throughput_per_Volume"] = df["DRB.UEThpDl"] / (df["DRB.RlcSduTransmittedVolumeDL"] + epsilon)
        new_features["Avg_RlcDelay"] = (df["DRB.RlcSduDelayDl"] + df["DRB.RlcDelayUl"]) / 2
        new_features["Delay_Imbalance"] = df["DRB.RlcSduDelayDl"] - df["DRB.RlcDelayUl"]
        new_features["CQI_Normalized"] = df["CQI"] / 15.0
        new_features["DelayJitterDl"] = df.groupby(["E2AgentID", "UE_ID"])["DRB.RlcSduDelayDl"].diff().fillna(0)
        new_features["DelayJitterUl"] = df.groupby(["E2AgentID", "UE_ID"])["DRB.RlcDelayUl"].diff().fillna(0)
        new_features["Zero_PRB_Flag"] = ((df["RRU.PrbUsedDl"] == 0) & (df["RRU.PrbUsedUl"] == 0)).astype(int)
        new_features["Zero_Throughput_Flag"] = ((df["DRB.UEThpDl"] == 0) & (df["DRB.UEThpUl"] == 0)).astype(int)
        new_features["Poor_Signal_Flag"] = ((df["CQI"] < 5) | (df["RSRP"] < -110) | (df["RSRQ"] < -15)).astype(int)
        new_features['Timestamp_epoch'] = df['Timestamp'].astype('int64') // 10**9
        df = pd.concat([df, pd.DataFrame(new_features)], axis=1)

        rolling_features_to_calculate = [
            "RRU.PrbUsedUl", "DRB.UEThpUl", "DRB.UEThpDl", "DRB.RlcSduTransmittedVolumeUL",
            "DRB.RlcSduTransmittedVolumeDL", "DRB.RlcSduDelayDl", "DRB.RlcDelayUl", "CQI", "RSRP",
            "UL_PRB_Efficiency", "DL_PRB_Efficiency", "UL_Throughput_per_Volume", "DL_Throughput_per_Volume",
            "Avg_RlcDelay", "Delay_Imbalance", "CQI_Normalized", "PRB_Utilization_Ratio_DL",
            "PRB_Utilization_Ratio_UL", "Resource_Imbalance", "Signal_Quality_Index",
            "Throughput_Asymmetry", "DelayJitterDl", "DelayJitterUl"
        ]
        flag_features = ["Zero_PRB_Flag", "Zero_Throughput_Flag", "Poor_Signal_Flag"]
        all_features_to_roll = rolling_features_to_calculate + flag_features

        window_size = 5
        final_dfs = []
        grouped = df.groupby(["E2AgentID", "UE_ID"])

        for (run, ue), group in grouped:
            group = group.set_index("Timestamp").sort_index()
            rolled_data = group[all_features_to_roll].rolling(window=window_size, min_periods=1).agg(["mean", "std"])
            rolled_data.columns = [f"{col}_{stat}" for col, stat in rolled_data.columns]
            rolled_data["E2AgentID"] = run
            rolled_data["UE_ID"] = ue
            rolled_data["Timestamp"] = group.index
            rolled_data["Timestamp_epoch"] = rolled_data["Timestamp"].astype('int64') // 10**9
            final_dfs.append(rolled_data.reset_index(drop=True))

        if not final_dfs:
            return pd.DataFrame()

        final_df = pd.concat(final_dfs, ignore_index=True)

        # selected_columns = [
        #     'RRU.PrbUsedUl_mean', 'RRU.PrbUsedUl_std', 'DRB.UEThpUl_mean', 'DRB.UEThpUl_std',
        #     'DRB.UEThpDl_mean', 'DRB.UEThpDl_std', 'DRB.RlcSduTransmittedVolumeUL_mean',
        #     'DRB.RlcSduTransmittedVolumeUL_std', 'DRB.RlcSduTransmittedVolumeDL_mean',
        #     'DRB.RlcSduTransmittedVolumeDL_std', 'DRB.RlcSduDelayDl_mean', 'DRB.RlcSduDelayDl_std',
        #     'DRB.RlcDelayUl_mean', 'DRB.RlcDelayUl_std', 'CQI_mean', 'CQI_std', 'RSRP_mean', 'RSRP_std',
        #     'UL_PRB_Efficiency_mean', 'UL_PRB_Efficiency_std', 'DL_PRB_Efficiency_mean',
        #     'DL_PRB_Efficiency_std', 'UL_Throughput_per_Volume_mean', 'UL_Throughput_per_Volume_std',
        #     'DL_Throughput_per_Volume_mean', 'DL_Throughput_per_Volume_std', 'Avg_RlcDelay_mean',
        #     'Avg_RlcDelay_std', 'Delay_Imbalance_mean', 'Delay_Imbalance_std', 'CQI_Normalized_mean',
        #     'CQI_Normalized_std', 'PRB_Utilization_Ratio_DL_mean', 'PRB_Utilization_Ratio_DL_std',
        #     'PRB_Utilization_Ratio_UL_mean', 'PRB_Utilization_Ratio_UL_std',
        #     'Resource_Imbalance_mean', 'Resource_Imbalance_std', 'Signal_Quality_Index_mean',
        #     'Signal_Quality_Index_std', 'Throughput_Asymmetry_mean', 'Throughput_Asymmetry_std',
        #     'DelayJitterDl_mean', 'DelayJitterDl_std', 'DelayJitterUl_mean', 'DelayJitterUl_std',
        #     'Zero_PRB_Flag_mean', 'Zero_PRB_Flag_std', 'Zero_Throughput_Flag_mean',
        #     'Zero_Throughput_Flag_std', 'Poor_Signal_Flag_mean', 'Poor_Signal_Flag_std', 'UE_ID', 'E2AgentID', 'Timestamp'
        # ]
        
        # selected_columns = ['DelayJitterUl_mean', 'DelayJitterUl_std', 'DelayJitterDl_mean', 'DelayJitterDl_std', 'UE_ID', 'DRB.RlcDelayUl_mean', 'Delay_Imbalance_mean', 'Avg_RlcDelay_mean', 'UL_Throughput_per_Volume_mean', 'DRB.RlcDelayUl_std', 'Avg_RlcDelay_std', 'Delay_Imbalance_std', 'UL_Throughput_per_Volume_std', 'UL_PRB_Efficiency_std', 'UL_PRB_Efficiency_mean', 'DRB.RlcSduTransmittedVolumeUL_std', 'DRB.UEThpUl_std', 'DRB.RlcSduDelayDl_mean', 'Throughput_Asymmetry_std', 'DRB.RlcSduDelayDl_std', 'DRB.UEThpUl_mean', 'Throughput_Asymmetry_mean', 'DRB.RlcSduTransmittedVolumeUL_mean', 'Signal_Quality_Index_mean', 'DL_Throughput_per_Volume_mean', 'DL_Throughput_per_Volume_std', 'RSRP_mean', 'Signal_Quality_Index_std', 'RSRP_std', 'DRB.RlcSduTransmittedVolumeDL_std']
        # final_selected_columns = [col for col in selected_columns if col in final_df.columns]
        # print("✅ Columns in final_df:", list(final_df.columns))
        # print("🔑 Expected columns:", selected_columns)
        # print("❌ Missing columns:", [col for col in selected_columns if col not in final_df.columns])
        # print("⚠️ Extra columns in final_df:", [col for col in final_df.columns if col not in selected_columns])
        # print("Shape of final_df:", final_df.shape)
        final_df = final_df.reindex(columns=self.selected_features, fill_value=0.0)
        # print("Final aligned shape:", final_df.shape)
        # print("Final columns:", final_df.columns.tolist())
        return final_df
    
    def predict_cascaded(self, feature_data):
        """
        Run Stage 1 → Stage 2 cascade on feature data.
        Output per-UE as:
        UE <id> → Malicious-<stage2_label>
        UE <id> → Benign-<stage2_label>
        """

        from collections import Counter

        if feature_data.empty:
            print("⚠️ No data for prediction")
            return

        ue_ids = feature_data['UE_ID'].values

        # Drop identifiers not used for prediction
        X_df = feature_data.drop(columns=['E2AgentID', 'UE_ID', 'Timestamp'], errors='ignore').copy()

        # Align to training feature order if available
        if getattr(self, 'selected_features', None):
            feat_list = [f for f in self.selected_features if f not in ('UE_ID', 'E2AgentID', 'Timestamp')]
            X_df = X_df.reindex(columns=feat_list, fill_value=0.0)

        # Convert to numeric
        X_df = X_df.apply(pd.to_numeric, errors='coerce').fillna(0.0)
        X_np = X_df.values.astype(np.float32)

        # --- Stage 1: binary classification ---
        if isinstance(self.s1_model, nn.Module):
            self.s1_model.eval()
            with torch.no_grad():
                out = self.s1_model(torch.tensor(X_np))
                if out.dim() == 1 or (out.dim() == 2 and out.shape[1] == 1):
                    probs = torch.sigmoid(out.squeeze())
                    binary_preds = (probs > 0.5).long().cpu().numpy()
                else:
                    binary_preds = out.argmax(dim=1).cpu().numpy()
        else:
            binary_preds = self.s1_model.predict(X_np)
            
        per_ue_stage1 = {}
        for ue in np.unique(ue_ids):
            ue_preds = [binary_preds[i] for i, uid in enumerate(ue_ids) if uid == ue]
            # majority vote
            most_common = Counter(ue_preds).most_common(1)[0][0]
            label = "Malicious" if most_common else "Benign"
            per_ue_stage1[int(ue)] = label

        # Print summary
        print("\n🔹 Stage 1 (Binary) Predictions per UE (Aggregated):")
        for ue, label in per_ue_stage1.items():
            print(f"UE {ue} → {label}")
            
        # --- Stage 2: refine with benign/malicious models ---
        final_preds = []
        for i, pred in enumerate(binary_preds):
            x_sample = X_np[[i]]  # keep shape (1, n_features)

            if pred == 0:  # benign branch
                if isinstance(self.s2_ben_model, nn.Module):
                    self.s2_ben_model.eval()
                    with torch.no_grad():
                        out = self.s2_ben_model(torch.tensor(x_sample))
                        pred_enc = out.argmax(dim=1).cpu().numpy()
                else:
                    pred_enc = self.s2_ben_model.predict(x_sample)
                print(f"Benign {pred_enc}")
                # decode label
                pred_label = self.le_benign[pred_enc[0]]
                final_preds.append(f"Benign-{pred_label}")

            else:  # malicious branch
                if isinstance(self.s2_mal_model, nn.Module):
                    self.s2_mal_model.eval()
                    with torch.no_grad():
                        out = self.s2_mal_model(torch.tensor(x_sample))
                        pred_enc = out.argmax(dim=1).cpu().numpy()
                else:
                    pred_enc = self.s2_mal_model.predict(x_sample)
                print(f"Malicious {pred_enc}")
                # decode label
                pred_label = self.le_malicious[pred_enc[0]]
                final_preds.append(f"Malicious-{pred_label}")

        # Attach row-level results
        feature_data = feature_data.copy()
        feature_data['cascade_prediction'] = final_preds

        # --- Per-UE aggregation ---
        per_ue_status = {}
        for ue in np.unique(ue_ids):
            ue_preds = feature_data[feature_data['UE_ID'] == ue]['cascade_prediction'].tolist()
            malicious_preds = [p for p in ue_preds if p.startswith("Malicious-")]

            if malicious_preds:  # pick most common malicious subtype
                subtypes = [m.split("-", 1)[1] for m in malicious_preds]
                chosen = Counter(subtypes).most_common(1)[0][0]
                per_ue_status[int(ue)] = f"Malicious-{chosen}"
            else:  # pick most common benign subtype
                benign_preds = [p for p in ue_preds if p.startswith("Benign-")]
                if benign_preds:
                    subtypes = [b.split("-", 1)[1] for b in benign_preds]
                    chosen = Counter(subtypes).most_common(1)[0][0]
                    per_ue_status[int(ue)] = f"Benign-{chosen}"
                else:
                    per_ue_status[int(ue)] = "Unknown-NA"

        # Print summary
        print("\n📊 Per-UE Cascaded Results:")
        for ue, status in per_ue_status.items():
            print(f"UE {ue} → {status}")

    # def predict_cascaded(self, feature_data):
    #     """
    #     Run Stage 1 → Stage 2 cascade on feature data.
    #     """
    #     if feature_data.empty:
    #         print("⚠️ No data for prediction")
    #         return

    #     ue_ids = feature_data['UE_ID'].values
    #     X = feature_data.drop(columns=['E2AgentID', 'Timestamp'], errors='ignore')

    #     # --- Stage 1: Binary prediction ---
    #     if isinstance(self.s1_model, nn.Module):  # PyTorch model
    #         self.s1_model.eval()
    #         with torch.no_grad():
    #             X_tensor = torch.tensor(X.values, dtype=torch.float32)
    #             binary_preds = self.s1_model(X_tensor).argmax(dim=1).cpu().numpy()
    #     else:  # sklearn-like model
    #         binary_preds = self.s1_model.predict(X.values)

    #     # --- Stage 2: Refine with benign/malicious model ---
    #     final_preds = []
    #     for i, pred in enumerate(binary_preds):
    #         x_sample = X.iloc[[i]].values

    #         if pred == 0:  # benign
    #             try:
    #                 self.s2_ben_model.eval()
    #                 with torch.no_grad():
    #                     out = self.s2_ben_model(torch.tensor(x_sample, dtype=torch.float32))
    #                     pred_enc = out.argmax(dim=1).cpu().numpy()
    #             except Exception:
    #                 pred_enc = self.s2_ben_model.predict(x_sample)
    #             final_preds.append(f"Benign_{pred_enc[0]}")

    #         else:  # malicious
    #             try:
    #                 self.s2_mal_model.eval()
    #                 with torch.no_grad():
    #                     out = self.s2_mal_model(torch.tensor(x_sample, dtype=torch.float32))
    #                     pred_enc = out.argmax(dim=1).cpu().numpy()
    #             except Exception:
    #                 pred_enc = self.s2_mal_model.predict(x_sample)
    #             final_preds.append(f"Malicious_{pred_enc[0]}")

    #     # Attach results
    #     feature_data['cascade_prediction'] = final_preds

    #     # Per-UE decision: majority vote or “if any malicious, mark malicious”
    #     per_ue_status = {}
    #     for ue_id in np.unique(ue_ids):
    #         ue_preds = feature_data[feature_data['UE_ID'] == ue_id]['cascade_prediction']
    #         if any("Malicious" in str(p) for p in ue_preds):
    #             per_ue_status[int(ue_id)] = "Malicious"
    #         else:
    #             per_ue_status[int(ue_id)] = "Benign"

    #     print("\n📊 Per-UE Cascaded Results:")
    #     for ue, status in per_ue_status.items():
    #         print(f"UE {ue} → {status}")

    def predict(self, feature_data):
        """
        Uses the loaded model to make predictions on the feature-engineered data
        and identifies malicious UEs (per-UE basis).
        """
        if self.model is None:
            print("  Model not loaded. Skipping prediction.")
            return

        if feature_data.empty:
            print("  - No feature data to process for prediction.")
            return

        print("\n🔬 Running prediction with loaded model...")
        
        ue_ids = feature_data['UE_ID'].values
        features_for_prediction = feature_data.drop(columns=['E2AgentID'], errors='ignore')

        try:
            X_tensor = torch.tensor(features_for_prediction.values, dtype=torch.float32)

            # Run inference
            self.model.eval()
            with torch.no_grad():
                logits = self.model(X_tensor)
                probs = torch.softmax(logits, dim=1)
                predictions = torch.argmax(probs, dim=1).cpu().numpy()

            # Attach predictions back
            feature_data['prediction'] = predictions

            # Group by UE_ID → decide malicious if any row is malicious
            per_ue_status = {}
            for ue_id in np.unique(ue_ids):
                ue_preds = feature_data[feature_data['UE_ID'] == ue_id]['prediction']
                if any(p in [1, "malicious"] for p in ue_preds):
                    per_ue_status[int(ue_id)] = "Malicious"
                else:
                    per_ue_status[int(ue_id)] = "Benign"

            # Print per UE status
            for ue_id, status in per_ue_status.items():
                print(f"⚡ UE {ue_id} → {status}")

            # Collect malicious UEs
            malicious_ue_ids = [ue for ue, status in per_ue_status.items() if status == "Malicious"]

            if malicious_ue_ids:
                print(f"\n🚨 Summary: Malicious activity detected from UEs: {malicious_ue_ids}")
            else:
                print("\n✅ No malicious activity detected in this batch.")

        except Exception as e:
            print(f"❌ Error during prediction: {e}")

    def subscription_callback(self, e2_agent_id, subscription_id, indication_hdr, indication_msg):
        """
        Callback triggered by RIC Indication. Buffers data and triggers feature engineering
        and model deployment when the buffer is full.
        """
        # print(f"\n📡 RIC Indication Received from {e2_agent_id} for Subscription ID: {subscription_id}")
        timestamp = datetime.now().isoformat()

        meas_data = self.e2sm_kpm.extract_meas_data(indication_msg)

        for ue_id, ue_meas_data in meas_data.get("ueMeasData", {}).items():
            row_dict = {
                "Timestamp": timestamp,
                "E2AgentID": e2_agent_id,
                "UE_ID": ue_id,
            }
            meas_values = ue_meas_data.get("measData", {})
            for metric in self.metric_names:
                raw_value = meas_values.get(metric)
                row_dict[metric] = self._extract_value(raw_value)
            self.data_buffer.append(row_dict)

        # print(f"📝 Buffer size: {len(self.data_buffer)}/{self.buffer_size}")
        print(f"📝 Buffer size: {len(self.data_buffer)}/{self.buffer_size}", end='\r', flush=True)

        if len(self.data_buffer) >= self.buffer_size:
            print(f"🔄 Buffer full. Processing {len(self.data_buffer)} records...")
            df = pd.DataFrame(self.data_buffer)
            
            features_df = self._feature_engineer_network_data(df)

            if len(self.data_buffer) >= self.buffer_size:
                print(f"\n🔄 Processing cumulative {len(self.data_buffer)} records...")
                df = pd.DataFrame(self.data_buffer)  # full buffer up to now
                features_df = self._feature_engineer_network_data(df)
                self.predict_cascaded(features_df)

            if len(self.data_buffer) >= 1440:
                print(f"\n🗑️ Buffer reached 1440 records. Clearing buffer...")
                self.data_buffer = []

    @xAppBase.start_function
    def start(self, e2_node_id, ue_ids, metric_names):
        """
        Entry point to start xApp subscription.
        """
        self.metric_names = metric_names

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
            self.subscription_callback
        )


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='KPM Style 5 xApp with in-memory feature engineering and prediction')
    parser.add_argument("--config", type=str, default='', help="xApp config file path")
    parser.add_argument("--http_server_port", type=int, default=8092, help="HTTP server listen port")
    parser.add_argument("--rmr_port", type=int, default=4562, help="RMR port")
    parser.add_argument("--s1_model_path", type=str, default="s1_model.joblib")
    parser.add_argument("--s2_ben_path", type=str, default="s2_benign_model.joblib")
    parser.add_argument("--s2_mal_path", type=str, default="s2_malicious_model.joblib")
    parser.add_argument("--buffer_size", type=int, default=30, help="Number of data points to buffer before processing")
    parser.add_argument("--e2_node_id", type=str, default='gnbd_001_001_00019b_0', help="E2 Node ID")
    parser.add_argument("--ran_func_id", type=int, default=2, help="RAN function ID")
    parser.add_argument("--ue_ids", type=str, default='0,1,2', help="Comma-separated list of UE IDs")
    parser.add_argument("--metrics", type=str, default='RRU.PrbAvailDl,RRU.PrbAvailUl,RRU.PrbUsedDl,RRU.PrbUsedUl,RACH.PreambleDedCell,DRB.UEThpDl,DRB.UEThpUl,DRB.RlcPacketDropRateDl,DRB.RlcSduTransmittedVolumeDL,DRB.RlcSduTransmittedVolumeUL,CQI,RSRP,RSRQ,DRB.RlcSduDelayDl,DRB.RlcDelayUl', help="Comma-separated list of metric names")

    args = parser.parse_args()

    ue_ids = list(map(int, args.ue_ids.split(",")))
    metric_names = args.metrics.split(",")

    kpmXapp = KpmStyle5Xapp(
        config=args.config,
        http_server_port=args.http_server_port,
        rmr_port=args.rmr_port,
        s1_model_path=args.s1_model_path,
        s2_ben_path=args.s2_ben_path,
        s2_mal_path=args.s2_mal_path,
        buffer_size=args.buffer_size
    )
    kpmXapp.e2sm_kpm.set_ran_func_id(args.ran_func_id)

    signal.signal(signal.SIGQUIT, kpmXapp.signal_handler)
    signal.signal(signal.SIGTERM, kpmXapp.signal_handler)
    signal.signal(signal.SIGINT, kpmXapp.signal_handler)

    print("🚀 Starting KPM Style 5 xApp...")
    kpmXapp.start(args.e2_node_id, ue_ids, metric_names)
    print("✅ xApp started. Awaiting RIC indications...")
