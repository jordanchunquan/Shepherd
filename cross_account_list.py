class CrossAccountList:
    def __init__(self) -> list[dict]:
        self.cross_account_list = [
            {
                "aws_account_name": "Network",
                "aws_account_id": "615042801495",
                "aws_account_role": "security_aws_scanner_role"
            },
            {
                "aws_account_name": "Log Archive",
                "aws_account_id": "410395959326",
                "aws_account_role": "security_aws_scanner_role"
            }
        ]