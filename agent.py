import subprocess
import os
from google.adk.agents import Agent

def run_firewall_script(server_ips: str, targetSubnet: str, app: str, env: str, input_file: str) -> str:
    """
    Executes the firewall script and then generates the Terraform variables.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define both script paths
    simplify_script = os.path.join(script_dir, 'Firewall_Simplify.py')
    tfvars_script = os.path.join(script_dir, 'generate_tfvars.py')
    
    final_summary = ""
    
    # --- PHASE 1: Data Processing ---
    try:
        result1 = subprocess.run(
            [
                'python', simplify_script, 
                '--server_ips', server_ips,
                '--subnet', targetSubnet,
                '--app', app,
                '--env', env,
                '--input_file', input_file,
            ], 
            capture_output=True, text=True, check=True
        )
        final_summary += f"✅ PHASE 1 COMPLETE:\n{result1.stdout}\n"
    except subprocess.CalledProcessError as e:
        return f"❌ Phase 1 (Data Processing) failed:\n{e.stderr}"
    except FileNotFoundError:
        return "Could not find Firewall_Simplify.py."

    # --- PHASE 2: Terraform Generation ---
    # This only runs if Phase 1 was completely successful
    try:
        result2 = subprocess.run(
            ['python', tfvars_script], 
            capture_output=True, text=True, check=True
        )
        final_summary += f"✅ PHASE 2 COMPLETE:\n{result2.stdout}"
    except subprocess.CalledProcessError as e:
        return final_summary + f"\n❌ Phase 2 (Terraform Generation) failed:\n{e.stderr}"
    except FileNotFoundError:
        return final_summary + "\nCould not find generate_tfvars.py."

    return final_summary

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