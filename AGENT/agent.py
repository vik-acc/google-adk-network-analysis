# import subprocess
# import os
# from google.adk.agents import Agent

# def run_firewall_script(server_ips: str, targetSubnet: str, app: str, env: str, input_file: str) -> str:
#     """
#     Executes the firewall script and then generates the Terraform variables.
#     """
#     script_dir = os.path.dirname(os.path.abspath(__file__))
    
#     # Define both script paths
#     simplify_script = os.path.join(script_dir, 'Firewall_Simplify.py')
#     tfvars_script = os.path.join(script_dir, 'generate_tfvars.py')
    
#     final_summary = ""
    
#     # --- PHASE 1: Data Processing ---
#     try:
#         result1 = subprocess.run(
#             [
#                 'python', simplify_script, 
#                 '--server_ips', server_ips,
#                 '--subnet', targetSubnet,
#                 '--app', app,
#                 '--env', env,
#                 '--input_file', input_file,
#             ], 
#             capture_output=True, text=True, check=True
#         )
#         final_summary += f"✅ PHASE 1 COMPLETE:\n{result1.stdout}\n"
#     except subprocess.CalledProcessError as e:
#         return f"❌ Phase 1 (Data Processing) failed:\n{e.stderr}"
#     except FileNotFoundError:
#         return "Could not find Firewall_Simplify.py."

#     # --- PHASE 2: Terraform Generation ---
#     # This only runs if Phase 1 was completely successful
#     try:
#         result2 = subprocess.run(
#             ['python', tfvars_script], 
#             capture_output=True, text=True, check=True
#         )
#         final_summary += f"✅ PHASE 2 COMPLETE:\n{result2.stdout}"
#     except subprocess.CalledProcessError as e:
#         return final_summary + f"\n❌ Phase 2 (Terraform Generation) failed:\n{e.stderr}"
#     except FileNotFoundError:
#         return final_summary + "\nCould not find generate_tfvars.py."

#     return final_summary

# # --- Agent Definition ---
# root_agent = Agent(
#     name="Network_Admin_Agent",
#     model="gemini-2.5-flash",
#     description="Assistant for managing firewall rules.",
#     instruction="""
#         You are a network administrator assistant. To build firewall rules, you must use the run_firewall_script tool.
        
#         Before running it, ask the user for:
#         1. server IPs (e.g., "10.13.48.62, 10.13.105.37")
#         2. targetSubnet (e.g., "10.0.0.0/24")
#         3. app (e.g., "orders")
#         4. env (e.g., "prod")
#         5. input_file (e.g., "input_file.xlsx")
        
#         Once you have all 5, execute the tool and give the user the summary.
#     """,
#     tools=[run_firewall_script]
# )

import os
import json
import io
import sys
import traceback

print("--- [SYSTEM] ATTEMPTING TO LOAD AGENT.PY ---")

try:
    from google.adk import Agent, tool
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaIoBaseDownload
    
    # Importing your custom scripts
    from Firewall_Simplify import process_firewall_traffic
    from generate_tfvars import generate_tfvars
    
    print("--- [SYSTEM] IMPORTS SUCCESSFUL ---")
    
except Exception as e:
    print("\n" + "!"*40)
    print("CRASH DURING AGENT IMPORT:")
    traceback.print_exc()
    print("!"*40 + "\n")

# --- GOOGLE DRIVE DOWNLOAD HELPER ---
# (Leave the rest of your file exactly as it was below here...)

# --- GOOGLE DRIVE DOWNLOAD HELPER ---
def download_from_drive(file_id, local_path):
    """Downloads a file from Google Drive using the Render Service Account."""
    creds_json = os.environ.get("GCP_SERVICE_ACCOUNT_JSON")
    if not creds_json:
        raise ValueError("GCP_SERVICE_ACCOUNT_JSON environment variable is missing!")
    
    creds_dict = json.loads(creds_json)
    SCOPES = ['https://www.googleapis.com/auth/drive.readonly']
    creds = service_account.Credentials.from_service_account_info(creds_dict, scopes=SCOPES)
    
    service = build('drive', 'v3', credentials=creds)
    request = service.files().get_media(fileId=file_id)
    
    with io.FileIO(local_path, 'wb') as fh:
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()
            print(f"Download Progress: {int(status.progress() * 100)}%")
            
    return local_path

# --- THE ADK TOOL ---
@tool
def process_network_analysis(file_id: str, server_ips: str, target_subnet: str, app_name: str, env: str):
    """
    Downloads firewall logs from Google Drive and generates Terraform variables.
    
    Args:
        file_id: The Google Drive File ID.
        server_ips: Comma separated list of server IPs.
        target_subnet: Target subnet CIDR.
        app_name: Name of the application.
        env: Target environment.
    """
    # 1. Save the file exactly where Firewall_Simplify expects it
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_filename = "traffic_logs.csv"
    local_input_path = os.path.join(script_dir, "data_input", input_filename)
    
    try:
        # STEP 1: Download from Drive
        print(f"System: Fetching Drive File ID {file_id}...")
        download_from_drive(file_id, local_input_path)
        
        # STEP 2: Execute firewall simplification
        print("System: Starting firewall traffic analysis...")
        fw_summary = process_firewall_traffic(
            server_ips=server_ips, 
            targetSubnet=target_subnet, 
            app=app_name, 
            env=env, 
            input_file=input_filename
        )
        
        # STEP 3: Execute Terraform generation
        print("System: Generating Terraform variables...")
        tf_summary = generate_tfvars("/tmp/Processed_Rules.xlsx", "/tmp/firewall.tfvars")
        
        # Combine the outputs for the agent to read back to you
        return f"{fw_summary}\n\n{tf_summary}\n\nThe final output is located at /tmp/firewall.tfvars"
    
    except Exception as e:
        print(f"Error: {str(e)}")
        return f"I encountered an error while processing the request: {str(e)}"

# --- AGENT DEFINITION ---
network_agent = Agent(
    name="Network_Admin_Agent",
    instructions=(
        "You are an expert Cloud Network Engineer specializing in firewall automation. "
        "Your primary task is to process network traffic logs and generate Terraform variables. "
        "You MUST collect ALL 5 of these parameters from the user before running the tool: "
        "1. Google Drive File ID "
        "2. Server IPs (comma separated) "
        "3. Target Subnet CIDR "
        "4. Application Name "
        "5. Environment (e.g., prod, dev) "
        "If any are missing, politely ask the user for them. "
        "Once you have all 5, call the process_network_analysis tool and report the summary back."
    ),
    tools=[process_network_analysis]
)