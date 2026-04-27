# # 
# import pandas as pd
# import ipaddress
# import numpy as np
# import socket
# import os
# import argparse

# # ================================
# # HELPER FUNCTIONS 
# # (Kept outside to keep the main function clean)
# # ================================
# def normalize_servers(server_str):
#     return [s.strip().lower() for s in server_str.split(",") if s.strip()]

# def ip_to_int(ip):
#     try:
#         return int(ipaddress.ip_address(ip))
#     except:
#         return None

# def get_service_name(port):
#     try:
#         return socket.getservbyport(int(port))
#     except:
#         return "Unregistered / Private Port"

# def standardize_port(p):
#     try:
#         p = int(p)
#         if 49152 <= p <= 65535:
#             return "49152-65535"
#         return p
#     except:
#         return p

# def map_service(p):
#     if p in [0, "49152-65535"] or pd.isna(p):
#         return ""
#     try:
#         return socket.getservbyport(int(p))
#     except:
#         return "Unregistered / Private Port"

# def build_rules(df, direction):
#     rules = pd.DataFrame()
#     rules["src_ip_ranges"] = df["LocalIP"]
#     rules["dest_ip_ranges"] = df["RemoteIP"]
#     rules["ports"] = df["RemotePort"]
#     rules["ip_protocol"] = df["Protocol"].str.lower()
#     rules["action"] = "allow"
#     rules["direction"] = direction
#     return rules

# # ================================
# # MAIN AGENT TOOL FUNCTION
# # ================================
# def process_firewall_traffic(servers: str, targetSubnet: str, app: str, env: str) -> str:
#     """
#     Processes network traffic files to build firewall rules based on provided parameters.
#     """
#     # 1. Get the exact folder where this script lives
#     script_dir = os.path.dirname(os.path.abspath(__file__))
    
#     # 2. Map input files
#     PRIMARY_FILE = os.path.join(script_dir, "input", "Scrubbed_Input.csv")
#     IPAM_FILE = os.path.join(script_dir, "input", "NetworkIPAM-scrubbed.xlsx")
#     COMMON_FILE = os.path.join(script_dir, "input", "Common_services.xlsx")

#     # ================================
#     # FETCH FILES
#     # ================================
#     df = pd.read_csv(PRIMARY_FILE)
#     ipam_df = pd.read_excel(IPAM_FILE)
#     common_ports = pd.read_excel(COMMON_FILE, sheet_name="Ignore_Ports")
#     common_ips = pd.read_excel(COMMON_FILE, sheet_name="Ignore_Ips")

#     # ================================
#     # VALIDATION
#     # ================================
#     required_cols = [
#         "LocalIP","RemoteIP","LocalVMName","RemoteVMName",
#         "LocalPort","RemotePort","Protocol"
#     ]

#     missing = [c for c in required_cols if c not in df.columns]
#     if missing:
#         raise ValueError(f"Missing required columns in Scrubbed_Input.csv: {missing}")

#     ipam_required = ["Address + prefix","Size","Start","End"]
#     missing_ipam = [c for c in ipam_required if c not in ipam_df.columns]
#     if missing_ipam:
#         raise ValueError(f"Missing IPAM columns: {missing_ipam}")

#     ipam_df = ipam_df.dropna(subset=ipam_required)

#     # ================================
#     # CLEANING
#     # ================================
#     drop_cols = [
#         "SampleRange","LocalAssetID","LocalGroups",
#         "RemoteAssetID","RemoteGroups","ConnectionCount"
#     ]

#     df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors='ignore')
#     df = df.drop_duplicates()

#     # ================================
#     # CLASSIFICATION
#     # ================================
#     servers_norm = normalize_servers(servers)

#     df["LocalVMName_norm"] = df["LocalVMName"].str.lower().str.strip()
#     df["RemoteVMName_norm"] = df["RemoteVMName"].str.lower().str.strip()

#     inbound = df[df["RemoteVMName_norm"].isin(servers_norm)].copy()
#     outbound = df[df["LocalVMName_norm"].isin(servers_norm)].copy()

#     # ================================
#     # PORT CORRECTION
#     # ================================
#     def swap(row):
#         row["LocalIP"], row["RemoteIP"] = row["RemoteIP"], row["LocalIP"]
#         row["LocalVMName"], row["RemoteVMName"] = row["RemoteVMName"], row["LocalVMName"]
#         row["LocalPort"], row["RemotePort"] = row["RemotePort"], row["LocalPort"]
#         return row

#     # inbound fix
#     move_rows = inbound[inbound["RemotePort"] == 0].copy()
#     inbound = inbound[inbound["RemotePort"] != 0]
#     move_rows = move_rows.apply(swap, axis=1)
#     outbound = pd.concat([outbound, move_rows])

#     # outbound fix
#     move_rows = outbound[outbound["RemotePort"] == 0].copy()
#     outbound = outbound[outbound["RemotePort"] != 0]
#     move_rows = move_rows.apply(swap, axis=1)
#     inbound = pd.concat([inbound, move_rows])

#     # ================================
#     # PORT STANDARDIZATION
#     # ================================
#     for col in ["LocalPort","RemotePort"]:
#         inbound[col] = inbound[col].apply(standardize_port)
#         outbound[col] = outbound[col].apply(standardize_port)

#     # ================================
#     # COMMON FILTERING
#     # ================================
#     ignore_ports = set(common_ports.iloc[:,0].dropna())
#     ignore_ips = set(common_ips.iloc[:,0].dropna())

#     inbound = inbound[~inbound["LocalIP"].isin(ignore_ips)]
#     outbound = outbound[~outbound["RemoteIP"].isin(ignore_ips)]

#     inbound = inbound[~inbound["RemotePort"].isin(ignore_ports)]
#     outbound = outbound[~outbound["RemotePort"].isin(ignore_ports)]

#     inbound = inbound.drop_duplicates()
#     outbound = outbound.drop_duplicates()

#     # ================================
#     # IPAM MATCHING
#     # ================================
#     ipam_df["Start_int"] = ipam_df["Start"].apply(ip_to_int)
#     ipam_df["End_int"] = ipam_df["End"].apply(ip_to_int)

#     def match_ip(ip):
#         ip_int = ip_to_int(ip)
#         if ip_int is None:
#             return None
#         matches = ipam_df[(ipam_df["Start_int"] <= ip_int) & (ipam_df["End_int"] >= ip_int)]
#         if matches.empty:
#             return None
#         return matches.sort_values("Size").iloc[0]["Address + prefix"]

#     # inbound mapping
#     inbound["Matched Network (Inbound)"] = inbound["LocalIP"].apply(match_ip)
#     inbound = inbound.dropna(subset=["Matched Network (Inbound)"])
#     inbound["LocalIP"] = inbound["Matched Network (Inbound)"]
#     inbound["RemoteIP"] = targetSubnet
#     inbound = inbound.drop(columns=["LocalVMName","RemoteVMName","LocalVMName_norm","RemoteVMName_norm"])

#     # outbound mapping
#     outbound["Matched Network (Outbound)"] = outbound["RemoteIP"].apply(match_ip)
#     outbound = outbound.dropna(subset=["Matched Network (Outbound)"])
#     outbound["RemoteIP"] = outbound["Matched Network (Outbound)"]
#     outbound["LocalIP"] = targetSubnet
#     outbound = outbound.drop(columns=["LocalVMName","RemoteVMName","LocalVMName_norm","RemoteVMName_norm"])

#     # ================================
#     # SERVICE MAPPING
#     # ================================
#     inbound["Remote Port Service"] = inbound["RemotePort"].apply(map_service)
#     outbound["Remote Port Service"] = outbound["RemotePort"].apply(map_service)

#     # ================================
#     # CREATE OUTPUT DIRECTORY (Safety Check)
#     # ================================
#     output_dir = os.path.join(script_dir, "output")
#     os.makedirs(output_dir, exist_ok=True) 

#     # ================================
#     # SAVE PROCESSED FILE
#     # ================================
#     PROCESSED_TRAFFIC = os.path.join(output_dir, "processed_traffic.xlsx")
#     with pd.ExcelWriter(PROCESSED_TRAFFIC) as writer:
#         df.to_excel(writer, sheet_name="Cleaned_Data", index=False)
#         inbound.to_excel(writer, sheet_name="Inbound", index=False)
#         outbound.to_excel(writer, sheet_name="Outbound", index=False)

#     # ================================
#     # FIREWALL BUILD
#     # ================================
#     in_rules = build_rules(inbound, "ingress")
#     out_rules = build_rules(outbound, "egress")

#     fw = pd.concat([in_rules, out_rules])
#     fw = fw.drop_duplicates(subset=[
#         "src_ip_ranges","dest_ip_ranges","ports","ip_protocol","direction"
#     ])

#     fw["rule_name"] = fw.apply(
#         lambda x: f"allow-{app}-{env}-{x['ports']}-{x['ip_protocol']}-{x['direction']}", axis=1
#     )
#     fw["description"] = fw["rule_name"]

#     fw = fw.groupby("rule_name").agg({
#         "src_ip_ranges": lambda x: ",".join(sorted(set(map(str,x)))),
#         "dest_ip_ranges": lambda x: ",".join(sorted(set(map(str,x)))),
#         "ports":"first",
#         "ip_protocol":"first",
#         "action":"first",
#         "direction":"first",
#         "description":"first"
#     }).reset_index()

#     fw_in = fw[fw["direction"]=="ingress"].copy()
#     fw_out = fw[fw["direction"]=="egress"].copy()

#     fw_in["priority"] = range(501, 501+len(fw_in))
#     fw_out["priority"] = range(601, 601+len(fw_out))

#     fw = pd.concat([fw_in, fw_out])
#     fw = fw.reset_index(drop=True)
#     fw["Sl. No."] = range(1, len(fw)+1)

#     fw = fw[[
#         "Sl. No.","priority","src_ip_ranges","dest_ip_ranges",
#         "ip_protocol","ports","action","direction","rule_name","description"
#     ]]

#     BUILD_FIREWALL = os.path.join(output_dir, "firewall-buildsheet.xlsx")
#     fw.to_excel(BUILD_FIREWALL, index=False)

#     # ================================
#     # SUMMARY RETURN
#     # ================================
#     summary = f"""
#     Processing Summary
#     ------------------
#     Application: {app} | Environment: {env}
#     Servers: {servers}
#     Target Subnet: {targetSubnet}
#     ------------------
#     Inbound rows mapped: {len(inbound)}
#     Outbound rows mapped: {len(outbound)}
#     Inbound rules: {len(fw_in)}
#     Outbound rules: {len(fw_out)}
#     Total firewall rules generated: {len(fw)}
    
#     Data Check:
#     Cleaned_Data shape: {df.shape}
#     Inbound shape: {inbound.shape}
#     Outbound shape: {outbound.shape}
#     """
    
#     return summary

# # ================================
# # TERMINAL EXECUTION BLOCK
# # ================================
# if __name__ == "__main__":
#     # 1. Set up the argument parser to catch the flags sent by subprocess
#     parser = argparse.ArgumentParser(description="Process Firewall Traffic")
#     parser.add_argument("--servers", required=True, help="Comma separated list of servers")
#     parser.add_argument("--subnet", required=True, help="Target subnet CIDR")
#     parser.add_argument("--app", required=True, help="Application name")
#     parser.add_argument("--env", required=True, help="Environment (e.g., prod, dev)")

#     # 2. Parse the arguments
#     args = parser.parse_args()

#     # 3. Pass them into your main function
#     summary_output = process_firewall_traffic(
#         servers=args.servers, 
#         targetSubnet=args.subnet, 
#         app=args.app, 
#         env=args.env
#     )
    
#     # 4. Print the result so subprocess.run(capture_output=True) can grab it
#     print(summary_output)

import pandas as pd
import ipaddress
import numpy as np
import socket
import os
import argparse
from collections import defaultdict

# ================================
# HELPER FUNCTIONS
# ================================
def normalize_ips(ip_str):
    return [s.strip() for s in ip_str.split(",") if s.strip()]

def ip_to_int(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except:
        return None

def get_service_name(port):
    try:
        return socket.getservbyport(int(port))
    except:
        return "Unregistered / Private Port"

def standardize_port(p):
    try:
        p = int(p)
        if 49152 <= p <= 65535:
            return "49152-65535"
        return p
    except:
        return p

def map_service(p):
    if p in [0, "49152-65535"] or pd.isna(p):
        return ""
    try:
        return socket.getservbyport(int(p))
    except:
        return "Unregistered / Private Port"

def build_rules(df, direction):
    rules = pd.DataFrame()
    rules["src_ip_ranges"] = df["LocalIP"]
    rules["dest_ip_ranges"] = df["RemoteIP"]
    rules["ports"] = df["RemotePort"]
    rules["ip_protocol"] = df["Protocol"].str.lower()
    rules["action"] = "allow"
    rules["direction"] = direction
    return rules

def format_ports_for_name(port_str):
    return str(port_str).replace(",", "_")

# ================================
# MAIN AGENT TOOL FUNCTION
# ================================
def process_firewall_traffic(server_ips: str, targetSubnet: str, app: str, env: str, input_file: str) -> str:
    """
    Processes network traffic files to build firewall rules based on provided IP parameters.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    PRIMARY_FILE = os.path.join(script_dir, "input", input_file)
    COMMON_FILE = os.path.join(script_dir, "input", "Common_services.xlsx")

    # ================================
    # FETCH FILES
    # ================================
    if PRIMARY_FILE.lower().endswith(".csv"):
        df = pd.read_csv(PRIMARY_FILE)
    elif PRIMARY_FILE.lower().endswith((".xlsx", ".xls")):
        df = pd.read_excel(PRIMARY_FILE)
    else:
        raise ValueError("Unsupported file format. Use CSV or Excel.")

    common_ports = pd.read_excel(COMMON_FILE, sheet_name="Ignore_Ports")
    common_ips = pd.read_excel(COMMON_FILE, sheet_name="Ignore_Ips")

    # ================================
    # DETECT & NORMALIZE INPUT FORMAT
    # ================================
    if "src_addr" in df.columns:
        df = df.rename(columns={
            "src_addr": "LocalIP",
            "src_port": "LocalPort",
            "dest_addr": "RemoteIP",
            "dest_port": "RemotePort",
            "src_name": "LocalVMName",
            "dest_name": "RemoteVMName",
            "protocol_name": "Protocol"
        })

        df["Protocol"] = df["Protocol"].apply(
            lambda x: "UDP" if "udp" in str(x).lower() else "TCP"
        )

    # ================================
    # VALIDATION
    # ================================
    required_cols = [
        "LocalIP","RemoteIP","LocalVMName","RemoteVMName",
        "LocalPort","RemotePort","Protocol"
    ]

    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    # ================================
    # CLEANING
    # ================================
    drop_cols = [
        "SampleRange","LocalAssetID","LocalGroups",
        "RemoteAssetID","RemoteGroups","ConnectionCount"
    ]

    df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors='ignore')
    df = df.drop_duplicates()

    # ================================
    # CLASSIFICATION (IP BASED)
    # ================================
    server_ips_norm = normalize_ips(server_ips)

    inbound = df[df["RemoteIP"].isin(server_ips_norm)].copy()
    outbound = df[df["LocalIP"].isin(server_ips_norm)].copy()

    # ================================
    # PORT CORRECTION
    # ================================
    def swap(row):
        row["LocalIP"], row["RemoteIP"] = row["RemoteIP"], row["LocalIP"]
        row["LocalVMName"], row["RemoteVMName"] = row["RemoteVMName"], row["LocalVMName"]
        row["LocalPort"], row["RemotePort"] = row["RemotePort"], row["LocalPort"]
        return row

    move_rows = inbound[inbound["RemotePort"] == 0].copy()
    inbound = inbound[inbound["RemotePort"] != 0]
    move_rows = move_rows.apply(swap, axis=1)
    outbound = pd.concat([outbound, move_rows])

    move_rows = outbound[outbound["RemotePort"] == 0].copy()
    outbound = outbound[outbound["RemotePort"] != 0]
    move_rows = move_rows.apply(swap, axis=1)
    inbound = pd.concat([inbound, move_rows])

    # ================================
    # PORT STANDARDIZATION
    # ================================
    for col in ["LocalPort","RemotePort"]:
        inbound[col] = inbound[col].apply(standardize_port)
        outbound[col] = outbound[col].apply(standardize_port)

    # ================================
    # COMMON FILTERING
    # ================================
    ignore_ports = set(common_ports.iloc[:,0].dropna())
    ignore_ips = set(common_ips.iloc[:,0].dropna())

    inbound = inbound[~inbound["LocalIP"].isin(ignore_ips)]
    outbound = outbound[~outbound["RemoteIP"].isin(ignore_ips)]

    inbound = inbound[~inbound["RemotePort"].isin(ignore_ports)]
    outbound = outbound[~outbound["RemotePort"].isin(ignore_ports)]

    inbound = inbound.drop_duplicates()
    outbound = outbound.drop_duplicates()

    # ================================
    # IPAM / SUBNET MAPPING
    # ================================
    inbound["RemoteIP"] = targetSubnet
    outbound["LocalIP"] = targetSubnet

    # ================================
    # SERVICE MAPPING
    # ================================
    inbound["Remote Port Service"] = inbound["RemotePort"].apply(map_service)
    outbound["Remote Port Service"] = outbound["RemotePort"].apply(map_service)

    # ================================
    # FIREWALL BUILD (ENHANCED MERGING)
    # ================================
    in_rules = build_rules(inbound, "ingress")
    out_rules = build_rules(outbound, "egress")

    fw = pd.concat([in_rules, out_rules])

    # STEP 1: PRIMARY MERGE
    fw = fw.groupby([
        "src_ip_ranges",
        "dest_ip_ranges",
        "ip_protocol",
        "direction"
    ]).agg({
        "ports": lambda x: ",".join(sorted(set(map(str, x)), key=lambda y: int(y.split("-")[0]) if str(y).isdigit() else 99999)),
        "action": "first"
    }).reset_index()

    # STEP 2: RULE NAME CREATION
    fw["rule_name"] = fw.apply(
        lambda x: f"allow-{app}-{env}-{format_ports_for_name(x['ports'])}-{x['ip_protocol']}-{x['direction']}",
        axis=1
    )
    fw["description"] = fw["rule_name"]

    # STEP 3: OPTIONAL SECONDARY MERGE
    fw = fw.groupby("rule_name").agg({
        "src_ip_ranges": lambda x: ",".join(sorted(set(map(str,x)))),
        "dest_ip_ranges": lambda x: ",".join(sorted(set(map(str,x)))),
        "ports": "first",
        "ip_protocol": "first",
        "action": "first",
        "direction": "first",
        "description": "first"
    }).reset_index()

    # RULE NAME SHORTENING LOGIC
    def shorten_rule_name(row, max_ports_in_name=3):
        ports = str(row["ports"]).split(",")
        if len(ports) <= max_ports_in_name:
            return row["rule_name"]
        base_ports = "_".join(ports[:max_ports_in_name])
        return f"allow-{app}-{env}-{base_ports}_more-{row['ip_protocol']}-{row['direction']}"

    fw["rule_name"] = fw.apply(shorten_rule_name, axis=1)

    # ENSURE UNIQUE RULE NAMES
    name_counter = defaultdict(int)
    new_names = []
    for name in fw["rule_name"]:
        name_counter[name] += 1
        if name_counter[name] == 1:
            new_names.append(name)
        else:
            new_names.append(f"{name}{name_counter[name]}")

    fw["rule_name"] = new_names
    fw["description"] = fw["rule_name"]

    # PRIORITY
    fw_in = fw[fw["direction"]=="ingress"].copy()
    fw_out = fw[fw["direction"]=="egress"].copy()

    fw_in["priority"] = range(501, 501+len(fw_in))
    fw_out["priority"] = range(601, 601+len(fw_out))

    fw = pd.concat([fw_in, fw_out])
    fw = fw.reset_index(drop=True)
    fw["Sl. No."] = range(1, len(fw)+1)

    fw = fw[[
        "Sl. No.","priority","src_ip_ranges","dest_ip_ranges",
        "ip_protocol","ports","action","direction","rule_name","description"
    ]]

    # ================================
    # SAVE FILES
    # ================================
    output_dir = os.path.join(script_dir, "output")
    os.makedirs(output_dir, exist_ok=True) 

    fw.to_excel(os.path.join(output_dir, "firewall-buildsheet.xlsx"), index=False)

    # ================================
    # SUMMARY RETURN
    # ================================
    summary = f"""
    Processing Summary
    ------------------
    Application: {app} | Environment: {env}
    Server IPs: {server_ips}
    Target Subnet: {targetSubnet}
    ------------------
    Inbound rows mapped: {len(inbound)}
    Outbound rows mapped: {len(outbound)}
    Inbound rules: {len(fw_in)}
    Outbound rules: {len(fw_out)}
    Total firewall rules generated: {len(fw)}
    """
    
    return summary

# ================================
# TERMINAL EXECUTION BLOCK
# ================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process Firewall Traffic")
    # Changed from --servers to --server_ips to reflect your new variable
    parser.add_argument("--server_ips", required=True, help="Comma separated list of server IPs")
    parser.add_argument("--subnet", required=True, help="Target subnet CIDR")
    parser.add_argument("--app", required=True, help="Application name")
    parser.add_argument("--env", required=True, help="Environment (e.g., prod, dev)")
    parser.add_argument("--input_file", required=True, help="Name of the input file (e.g., traffic_logs.csv)")

    args = parser.parse_args()

    summary_output = process_firewall_traffic(
        server_ips=args.server_ips, 
        targetSubnet=args.subnet, 
        app=args.app, 
        env=args.env,
        input_file=args.input_file
    )
    
    print(summary_output)