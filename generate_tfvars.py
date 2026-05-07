import pandas as pd
import ipaddress
import os

def validate_cidr_list(cidr_list, row_num, field_name):
    validated = []
    for cidr in cidr_list:
        cidr = cidr.strip()
        try:
            ipaddress.ip_network(cidr, strict=False)
            validated.append(cidr)
        except Exception:
            raise ValueError(f"Row {row_num}: Invalid {field_name} -> {cidr}")
    return validated

def validate_ports(ports, row_num):
    if not ports or str(ports).strip() == "":
        raise ValueError(f"Row {row_num}: ports cannot be empty")
    port_list = [p.strip() for p in str(ports).split(",")]
    return port_list

def process_file(file_path):
    if file_path.endswith(".csv"):
        df = pd.read_csv(file_path)
    else:
        df = pd.read_excel(file_path)

    ingress_rules = {}
    egress_rules = {}
    rule_names = set()

    for idx, row in df.iterrows():
        row_num = idx + 1
        rule_name = str(row["rule_name"]).strip()
        priority = row["priority"]
        action = str(row["action"]).strip()
        direction = str(row["direction"]).strip().lower()
        protocol = str(row["ip_protocol"]).strip()
        description = str(row["description"]).strip()

        if not str(priority).isdigit():
            raise ValueError(f"Row {row_num}: priority must be numeric")
        if direction not in ["ingress", "egress"]:
            raise ValueError(f"Row {row_num}: invalid direction -> {direction}")
        if not protocol:
            raise ValueError(f"Row {row_num}: protocol cannot be empty")
        if rule_name in rule_names:
            raise ValueError(f"Row {row_num}: duplicate rule_name -> {rule_name}")
        
        rule_names.add(rule_name)

        src_ips = validate_cidr_list(str(row["src_ip_ranges"]).split(","), row_num, "src_ip_ranges")
        dest_ips = validate_cidr_list(str(row["dest_ip_ranges"]).split(","), row_num, "dest_ip_ranges")
        ports = validate_ports(row["ports"], row_num)

        rule = {
            "priority": int(priority),
            "action": action,
            "src_ip_ranges": src_ips,
            "dest_ip_ranges": dest_ips,
            "protocol": protocol,
            "ports": ports,
            "description": description,
        }

        if direction == "ingress":
            ingress_rules[rule_name] = rule
        else:
            egress_rules[rule_name] = rule

    return ingress_rules, egress_rules

def format_tf_map(name, rules_dict):
    lines = [f"{name} = {{"]
    for rule_name, rule in rules_dict.items():
        lines.append(f'  "{rule_name}" = {{')
        lines.append(f"    priority = {rule['priority']}")
        lines.append(f'    action = "{rule["action"]}"')
        src = ",".join([f'"{x}"' for x in rule["src_ip_ranges"]])
        dest = ",".join([f'"{x}"' for x in rule["dest_ip_ranges"]])
        ports = ",".join([f'"{x}"' for x in rule["ports"]])
        lines.append(f"    src_ip_ranges = [{src}]")
        lines.append(f"    dest_ip_ranges = [{dest}]")
        lines.append(f'    protocol = "{rule["protocol"]}"')
        lines.append(f"    ports = [{ports}]")
        lines.append(f'    description = "{rule["description"]}"')
        lines.append("  },")
    lines.append("}")
    return "\n".join(lines)

def generate_tfvars(input_file, output_file):
    ingress_rules, egress_rules = process_file(input_file)
    ingress_block = format_tf_map("ingress_rules", ingress_rules)
    egress_block = format_tf_map("egress_rules", egress_rules)
    
    output = ingress_block + "\n\n" + egress_block
    
    with open(output_file, "w") as f:
        f.write(output)
    
    return f"Terraform file generated successfully: {output_file}"

# ================================
# TERMINAL EXECUTION BLOCK
# ================================
if __name__ == "__main__":
    # Dynamically find the output folder just like the first script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_path = os.path.join(script_dir, "output", "firewall-buildsheet.xlsx")
    output_path = os.path.join(script_dir, "output", "firewall.tfvars")
    
    try:
        # Run the generator and print the success message for the agent to catch
        result_message = generate_tfvars(input_path, output_path)
        print(result_message)
    except Exception as e:
        print(f"TFVARS GENERATION FAILED: {str(e)}")