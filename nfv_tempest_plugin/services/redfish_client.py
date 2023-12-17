import redfish


class RedfishClient:
    def __init__(self, ip, username, password):
        self.ip = ip
        self.username = username
        self.password = password
        self.client = None

    def connect(self):
        """Connect to the Redfish server"""
        self.client = redfish.redfish_client(
            base_url=f"https://{self.ip}",
            username=self.username,
            password=self.password,
            default_prefix='/redfish/v1'
        )
        self.client.login(auth="session")

    def get_power_state(self):
        """Get the power state of the server"""
        # Get the chassis information
        chassis_response = self.client.get("/redfish/v1/Chassis/", None)
        if chassis_response.status != 200:
            raise Exception("Failed to get chassis information")

        # Extract the @odata_id of the first member in the chassis
        chassis_member = chassis_response.dict.get("Members", [])[0]
        chassis_member_id = chassis_member.get("@odata.id")
        if not chassis_member_id:
            raise Exception("No members found in chassis data")

        # Now, get the power data for the first chassis member
        power_data_response = self.client.get(
            chassis_member_id + "/Power/", None
        )
        if power_data_response.status != 200:
            raise Exception("Failed to get power data")

        # Extract the PowerConsumedWatts from PowerControl
        power_control = power_data_response.dict.get("PowerControl", [])[0]
        power_consumed_watts = power_control.get("PowerConsumedWatts")
        return power_consumed_watts

    def disconnect(self):
        """Disconnect from the Redfish server"""
        if self.client:
            self.client.logout()
