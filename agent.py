# import subprocess
# from .Firewall_Simplify import process_firewall_traffic
# from google.adk.agents import Agent
# import os

# def run_firewall_script(servers: str, targetSubnet: str, app: str, env: str) -> str:
#     """
#     Executes the firewall script as an external process.
#     """
#     script_dir = os.path.dirname(os.path.abspath(__file__))
    
#     # 2. Attach the exact file name to that folder path
#     # script_path = os.path.join(script_dir, 'firewall-simplify.py')
#     script_path = os.path.join(script_dir, 'Firewall_Simplify.py')
#     try:
#         # We pass the variables as command-line flags, just like typing:
#         # python Firewall-Simplify.py --servers "VM-1" --subnet "10.0" ...
#         result = subprocess.run(
#             [
#                 'python', script_path, 
#                 '--servers', servers,
#                 '--subnet', targetSubnet,
#                 '--app', app,
#                 '--env', env
#             ], 
#             capture_output=True, 
#             text=True, 
#             check=True
#         )
#         return f"Success! Output:\n{result.stdout}"
        
#     except subprocess.CalledProcessError as e:
#         return f"Script failed with error:\n{e.stderr}"
#     except FileNotFoundError:
#         return "Could not find Firewall-Simplify.py. Ensure it is in the same directory."

# # --- Agent Definition ---
# root_agent = Agent(
#     name="Network_Admin_Agent",
#     model="gemini-2.5-flash",
#     description="Assistant for managing firewall rules.",
#     instruction="""
#         You are a network administrator assistant. To build firewall rules, you must use the run_firewall_script tool.
        
#         Before running it, ask the user for:
#         1. servers
#         2. targetSubnet
#         3. app
#         4. env
        
#         Once you have all 4, execute the tool and give the user the summary.
#     """,
#     tools=[run_firewall_script]
# )

import subprocess
import os
from google.adk.agents import Agent

def run_firewall_script(server_ips: str, targetSubnet: str, app: str, env: str, input_file: str) -> str:
    """
    Executes the firewall script as an external process.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Attach the exact file name to that folder path
    script_path = os.path.join(script_dir, 'Firewall_Simplify.py')
    
    try:
        # We pass the variables as command-line flags matching the new argparse setup
        result = subprocess.run(
            [
                'python', script_path, 
                '--server_ips', server_ips,  # <-- CHANGED THIS FLAG
                '--subnet', targetSubnet,
                '--app', app,
                '--env', env,
                '--input_file', input_file,
            ], 
            capture_output=True, 
            text=True, 
            check=True
        )
        return f"Success! Output:\n{result.stdout}"
        
    except subprocess.CalledProcessError as e:
        return f"Script failed with error:\n{e.stderr}"
    except FileNotFoundError:
        return "Could not find Firewall_Simplify.py. Ensure it is in the same directory."

# --- Agent Definition ---
root_agent = Agent(
    name="Network_Admin_Agent",
    model="gemini-2.5-flash",
    description="Assistant for managing firewall rules.",
    instruction="""
        You are a network administrator assistant. To build firewall rules, you must use the run_firewall_script tool.
        
        Before running it, ask the user for:
        1. server IPs (e.g., "10.13.48.62, 10.13.105.37")
        2. targetSubnet (e.g., "10.0.0.0/24")
        3. app (e.g., "orders")
        4. env (e.g., "prod")
        5. input_file (e.g., "input_file.xlsx")
        
        Once you have all 5, execute the tool and give the user the summary.
    """,
    tools=[run_firewall_script]
)