import re

class ParameterValidation:
    def validate_parameter(self, service: str, control_id: str, compliance: str, severity: str) -> bool:
        # Validate control id
        if not re.match(service + r'\.\d+$', control_id):
            print(f"Error: Invalid control id '{control_id}'")
            return False
        # Validate compliance status
        if compliance not in ('passed', 'failed', 'not_found'):
            print(f"Error: Invalid compliance status '{compliance}'")
            return False
        # Validate severity
        if severity not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            print(f"Error: Invalid severity '{severity}'")
            return False
        return True
    
    def validate_arg_parser(self, arg_parser: str) -> bool:
        if arg_parser != "y":
            return False
        return True
    
    def validate_input_account_name(self, input_account_name: str) -> bool:
        if not any([re.match(r'^[a-z_]+$', input_account_name), re.match(r'^[a-z]+$', input_account_name)]):
            return False
        return True
    
    def require_tag_key(self) -> list[str]:
        return ["Application", "Department", "Description", "Environment", "Owner", "Platform", "Platform PIC"]