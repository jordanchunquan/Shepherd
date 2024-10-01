class CrossAccountList:
    def __init__(self) -> list[dict]:
        self.cross_account_list = [
            {
                "aws_account_name": "example_account_1",
                "aws_account_id": "XXXXXXXXXXXX",
                "aws_account_role": "example_role"
            },
            {
                "aws_account_name": "example_account_2",
                "aws_account_id": "XXXXXXXXXXXX",
                "aws_account_role": "example_role"
            }
        ]