"""API for Neo Smart Blinds (Cloud)."""
import httpx
import logging
import base64
import json
import time
import secrets

from homeassistant.core import HomeAssistant
from homeassistant.const import CONF_USERNAME, CONF_PASSWORD
from homeassistant.exceptions import ConfigEntryAuthFailed

from .const import (
    DOMAIN,
    API_TOKEN_URL,
    API_LOCATION_URL,
    API_COMMAND_URL,
    API_SCHEDULE_UPDATE_URL, 
    CLIENT_ID,
    CMD_UP,
    CMD_DOWN,
    CMD_STOP,
    CMD_FAV,
)

_LOGGER = logging.getLogger(__name__)

# Timeout configuration for all API requests
REQUEST_TIMEOUT = httpx.Timeout(15.0, connect=5.0, read=10.0)
REQUEST_TIMEOUT_SECONDS = 15.0

#
# --- SECURITY: LOG SANITIZATION ---
#
def _sanitize_for_logging(data):
    """Remove sensitive data before logging to prevent exposure in logs."""
    if data is None:
        return None
    
    # List of sensitive keys to redact
    sensitive_keys = {
        'access_token', 'refresh_token', 'password', 'hash', 
        'token', 'authorization', 'bearer'
    }
    
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                sanitized[key] = '***REDACTED***'
            elif isinstance(value, (dict, list)):
                sanitized[key] = _sanitize_for_logging(value)
            else:
                sanitized[key] = value
        return sanitized
    elif isinstance(data, list):
        return [_sanitize_for_logging(item) for item in data]
    else:
        return data

# --- END SECURITY ---

#
# --- HELPER FUNCTION FOR SCHEDULE NAMES ---
#
def _get_friendly_command_name(command: str) -> str:
    """Translate a command code to a friendly name."""
    
    # Map from command codes (like in const.py) to names
    cmd_map = {
        "up": "Open",
        "dn": "Close",
        "sp": "Stop",
        "i1": "Favorite 1",
        "i2": "Favorite 2",
        "gp": "Favorite (GP)",
        "cl": "Close", # From your log data
        "u4": "Middle Up",
        "d4": "Middle Down",
        "u2": "Lower Up",
        "d2": "Lower Down"
    }

    friendly_name = cmd_map.get(command)
    if friendly_name:
        return friendly_name
        
    # Check for position command (e.g., "75")
    if command.isdigit():
        return f"Position {command}%"
        
    return command.upper() # Fallback, e.g., "FAV_1"

# --- END HELPER FUNCTION ---


class NeoSmartCloudAuthError(ConfigEntryAuthFailed):
    """Exception for authentication errors."""

class NeoSmartCloudAPI:
    """A client for the Neo Smart Blinds Cloud API."""

    def __init__(self, hass: HomeAssistant, data: dict, client: httpx.AsyncClient):
        """Initialize the API client."""
        self.hass = hass
        self._username = data[CONF_USERNAME]
        self._password = data[CONF_PASSWORD]
        self._access_token = None
        self._refresh_token = None
        self._user_uuid = None 
        self._client = client
        self._controller_map = {} 

    def get_user_uuid(self) -> str | None:
        """Return the user's UUID."""
        return self._user_uuid

    def _decode_token(self, token: str, key: str):
        """Decode a JWT and extract a specific key."""
        try:
            payload_b64 = token.split('.')[1]
            payload_b64 += '=' * (-len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            payload_data = json.loads(payload_json)
            
            value = payload_data.get(key)
            if not value:
                _LOGGER.error("Token payload did not contain '%s' key", key)
                return None
            return value
            
        except Exception as err:
            _LOGGER.error("Failed to decode token: %s", err)
            return None

    def _generate_hash(self) -> str:
        """
        Generate the 7-digit hash required by the API.
        Per the official documentation: "A simple implementation is taking the last 7 digits
        from time.now() in milliseconds."
        
        Enhanced with additional entropy for improved security.
        """
        try:
            # Use timestamp as base (as required by API)
            time_ms = str(int(time.time() * 1000))
            base_hash = time_ms[-7:]
            
            # Add cryptographically secure random component for additional entropy
            # Mix it with the timestamp to maintain API compatibility
            random_component = secrets.randbelow(100)
            
            # Combine timestamp with random component while keeping 7 digits
            enhanced_hash = str((int(base_hash) + random_component) % 10000000).zfill(7)
            
            _LOGGER.debug("Generated hash (timestamp-based with entropy)")
            return enhanced_hash
            
        except Exception as err:
            _LOGGER.error("Failed to generate hash: %s", err)
            # Fallback to secure random 7-digit number
            return str(secrets.randbelow(9000000) + 1000000)

    async def async_login(self) -> None:
        """Log in to the API and store the auth tokens."""
        _LOGGER.debug("Attempting to log in to Neo Smart Blinds cloud")
        
        payload = {
            "grant_type": "password",
            "username": self._username,
            "password": self._password,
            "client_id": CLIENT_ID, 
        }
        
        headers = {
            "Origin": "https://app.neosmartblinds.com",
            "Referer": "https://app.neosmartblinds.com/"
        }

        try:
            response = await self._client.post(API_TOKEN_URL, data=payload, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
            response.raise_for_status()
            
            data = response.json()
            if "access_token" not in data or "refresh_token" not in data:
                _LOGGER.error("Login response missing tokens: %s", data)
                raise NeoSmartCloudAuthError("Login failed, response missing tokens")
                
            self._access_token = data["access_token"]
            self._refresh_token = data["refresh_token"]
            
            self._user_uuid = self._decode_token(self._access_token, "usr")
            if not self._user_uuid:
                raise NeoSmartCloudAuthError("Login succeeded, but failed to parse user UUID from token")

            self._parse_controller_map_from_token(self._access_token)
            
            _LOGGER.info("Successfully logged in to Neo cloud")
            
        except httpx.HTTPStatusError as err:
            _LOGGER.error("Login failed: %s", err)
            raise NeoSmartCloudAuthError("Login failed, check credentials")
        except Exception as err:
            _LOGGER.error("Login request failed: %s", err)
            raise

    async def async_refresh_token(self) -> bool:
        """Refresh the access token using the refresh token."""
        _LOGGER.debug("Refreshing Neo cloud access token")
        
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token,
            "client_id": CLIENT_ID,
        }
        
        headers = {
            "Origin": "https://app.neosmartblinds.com",
            "Referer": "https://app.neosmartblinds.com/"
        }
        
        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as refresh_client:
                response = await refresh_client.post(API_TOKEN_URL, data=payload, headers=headers)
            
            response.raise_for_status()
            data = response.json()
            
            if "access_token" not in data or "refresh_token" not in data:
                _LOGGER.error("Refresh response missing tokens: %s", data)
                return False
                
            self._access_token = data["access_token"]
            self._refresh_token = data["refresh_token"]
            
            self._user_uuid = self._decode_token(self._access_token, "usr")
            if not self._user_uuid:
                return False

            self._parse_controller_map_from_token(self._access_token)
                
            _LOGGER.debug("Successfully refreshed Neo cloud token")
            return True
            
        except Exception:
            _LOGGER.error("Failed to refresh token, re-login required", exc_info=True)
            return False

    async def _api_request(self, method: str, url: str, **kwargs):
        """Make an authenticated API request, handling token refresh."""
        if not self._access_token:
            await self.async_login()
            
        headers = kwargs.get("headers", {})
        headers["Authorization"] = f"Bearer {self._access_token}"
        headers["Origin"] = "https://app.neosmartblinds.com"
        headers["Referer"] = "https://app.neosmartblinds.com/"
        kwargs["headers"] = headers
            
        try:
            # Use consistent timeout configuration
            kwargs.setdefault('timeout', REQUEST_TIMEOUT)
            
            response = await self._client.request(method, url, **kwargs)
            if response.status_code == 401:  # Token expired
                _LOGGER.debug("Token expired, attempting refresh")
                if not await self.async_refresh_token():
                    raise NeoSmartCloudAuthError("Token refresh failed")
                
                headers["Authorization"] = f"Bearer {self._access_token}"
                kwargs["headers"] = headers
                
                response = await self._client.request(method, url, **kwargs)
            
            response.raise_for_status()
            return response
            
        except httpx.HTTPStatusError as err:
            _LOGGER.error("API request failed: %s", err)
            raise
        except Exception as err:
            _LOGGER.error("API request failed: %s", err)
            raise

    def _parse_controller_map_from_token(self, access_token: str):
        """Parse the access token to build the controller UUID-to-String map."""
        try:
            controller_strings = self._decode_token(access_token, "ctrv2")
            if not controller_strings:
                _LOGGER.error("Could not parse controller strings (ctrv2) from access token")
                return
                
            for full_string in controller_strings:
                uuid = full_string.split(',')[0]
                self._controller_map[uuid] = full_string
            
            _LOGGER.debug("Built controller map: %s", self._controller_map)

        except Exception as err:
            _LOGGER.error("Failed to parse controller map: %s", err)

    async def async_get_data(self) -> dict:
        """Get all user data (blinds, schedules) from the cloud."""
        
        url = f"{API_LOCATION_URL}/{self._user_uuid}"
        response = await self._api_request("GET", url)
        data = response.json()
        
        # Log sanitized version to avoid exposing sensitive data
        _LOGGER.debug("API data received (sanitized): %s", _sanitize_for_logging(data))
        
        return data

    async def async_send_command(self, controller_id: str, blind_code: str, command: str) -> bool:
        """Send a command to a specific blind."""
        
        full_id_string = self._controller_map.get(controller_id)
        if not full_id_string:
            _LOGGER.error("No controller string found for UUID %s", controller_id)
            return False
            
        try:
            token, channel = blind_code.split('-')
        except ValueError:
            _LOGGER.error("Invalid blind_code format: %s", blind_code)
            return False
            
        hash_string = self._generate_hash()
        url = API_COMMAND_URL
        
        payload = {
            full_id_string: [
                {
                    "token": token,
                    "command": command,
                    "channel": channel,
                    "motor": "no",
                    "hash": hash_string
                }
            ]
        }

        _LOGGER.debug("Sending command to %s with payload: %s", url, _sanitize_for_logging(payload))

        try:
            await self._api_request("POST", url, json=payload)
            _LOGGER.info("Command sent successfully")
            return True
        except Exception:
            _LOGGER.error("Failed to send command. Payload was: %s", _sanitize_for_logging(payload), exc_info=True)
            return False

    async def async_set_schedule_state(self, schedule_id: str, enabled: bool) -> bool:
        """Set the enabled state of a schedule."""
        _LOGGER.debug("Setting schedule %s to %s", schedule_id, enabled)
        
        url = API_SCHEDULE_UPDATE_URL.format(uuid=self._user_uuid, schedule_id=schedule_id)
        payload = {"enabled": enabled} 

        try:
            await self._api_request("POST", url, json=payload)
            _LOGGER.info("Schedule state set successfully")
            return True
        except Exception:
            _LOGGER.error("Failed to set schedule state", exc_info=True)
            return False

def parse_blinds_from_data(data: dict) -> list:
    """Parse the blinds list from the full data payload with validation."""
    blinds_list = []
    
    # Validate input data type
    if not isinstance(data, dict):
        _LOGGER.error("Invalid data format: expected dict, got %s", type(data).__name__)
        return []
    
    rooms = data.get("rooms", {})
    if not isinstance(rooms, dict):
        _LOGGER.error("Invalid rooms format: expected dict, got %s", type(rooms).__name__)
        return []
    
    if not rooms:
        _LOGGER.warning("No rooms found in API response")
        return []

    for room_id, room in rooms.items():
        # Validate room is a dict
        if not isinstance(room, dict):
            _LOGGER.warning("Skipping invalid room %s: not a dict", room_id)
            continue
            
        controller_id = room.get("controller") 
        room_token = room.get("token") 
        room_name = room.get("name")
        
        # Validate required fields
        if not controller_id or not isinstance(controller_id, str):
            _LOGGER.warning("Skipping room %s: invalid controller_id", room_id)
            continue
        
        if not room_token or not isinstance(room_token, str):
            _LOGGER.warning("Skipping room %s: invalid room_token", room_id)
            continue
            
        blinds = room.get("blinds", {})
        if not isinstance(blinds, dict):
            _LOGGER.warning("Skipping room %s: invalid blinds format", room_id)
            continue
            
        for channel, blind in blinds.items():
            if not blind: # Skip empty blind slots (like '01': None)
                continue
            
            # Validate blind is a dict
            if not isinstance(blind, dict):
                _LOGGER.warning("Skipping invalid blind in room %s channel %s", room_id, channel)
                continue
            
            blind_name = blind.get("name")
            if not blind_name or not isinstance(blind_name, str):
                blind_name = f"Blind {channel}"
            
            # Validate channel format
            try:
                blind_code = f"{room_token}-{channel.zfill(2)}"
            except (AttributeError, ValueError) as err:
                _LOGGER.warning("Skipping blind with invalid channel %s: %s", channel, err)
                continue
            
            motor_code = blind.get("motorCode", "unknown")
            if not isinstance(motor_code, str):
                motor_code = "unknown"
                
            is_tdbu = blind.get("tdbu", False)
            if not isinstance(is_tdbu, bool):
                is_tdbu = False
            
            has_percent = blind.get("hasPercent", False)
            if not isinstance(has_percent, bool):
                has_percent = False
            
            blinds_list.append({
                "unique_id": f"{controller_id}_{blind_code}",
                "name": blind_name,
                "room_name": room_name if room_name else "Unknown Room",
                "blind_code": blind_code,
                "controller_id": controller_id,
                "has_percent": has_percent,
                "motor_code": motor_code,
                "is_tdbu": is_tdbu,
            })
            
    return blinds_list

def parse_schedules_from_data(data: dict) -> list:
    """Parse the schedules list from the full data payload with validation."""
    schedules_list = []
    
    # Validate input data type
    if not isinstance(data, dict):
        _LOGGER.error("Invalid data format: expected dict, got %s", type(data).__name__)
        return []
    
    schedules = data.get("schedules", {})
    if not isinstance(schedules, dict):
        _LOGGER.error("Invalid schedules format: expected dict, got %s", type(schedules).__name__)
        return []
        
    rooms = data.get("rooms", {})
    if not isinstance(rooms, dict):
        _LOGGER.warning("Invalid rooms format in schedules parsing")
        rooms = {}
    
    if not schedules:
        _LOGGER.info("No schedules found in API response")
        return []

    for schedule_id, schedule in schedules.items():
        # Validate schedule is a dict
        if not isinstance(schedule, dict):
            _LOGGER.warning("Skipping invalid schedule %s: not a dict", schedule_id)
            continue
        
        friendly_name = f"Schedule {schedule_id}" # Start with a fallback
        try:
            schedule_time = schedule.get("time", "Unknown Time")
            if not isinstance(schedule_time, str):
                schedule_time = str(schedule_time)
                
            schedule_cmd = schedule.get("command", "cmd")
            if not isinstance(schedule_cmd, str):
                schedule_cmd = "cmd"
                
            room_id = schedule.get("room") # This is the link

            room_name = "Unknown Room" # Fallback
            if room_id and room_id in rooms and isinstance(rooms[room_id], dict):
                room_name = rooms[room_id].get("name", room_name)
                if not isinstance(room_name, str):
                    room_name = "Unknown Room"
            
            command_name = _get_friendly_command_name(schedule_cmd) # e.g., "Favorite 1"
            friendly_name = f"{room_name} {command_name} at {schedule_time}"
        
        except Exception as e:
            _LOGGER.warning("Could not parse friendly name for schedule %s: %s", schedule_id, e)

        schedule_data = schedule.copy()
        schedule_data["id"] = schedule_id
        
        if room_id and room_id in rooms and isinstance(rooms[room_id], dict):
            schedule_data["room_name"] = rooms[room_id].get("name", "Unknown")
            schedule_data["controller_id"] = rooms[room_id].get("controller")
        
        schedule_data["name"] = friendly_name
        schedules_list.append(schedule_data)
            
    return schedules_list

def parse_controllers_from_data(data: dict) -> list:
    """Parse a unique list of controllers from the data payload with validation."""
    controllers = {} # Use a dict to store unique controllers
    
    # Validate input data type
    if not isinstance(data, dict):
        _LOGGER.error("Invalid data format: expected dict, got %s", type(data).__name__)
        return []
    
    rooms = data.get("rooms", {})
    if not isinstance(rooms, dict):
        _LOGGER.error("Invalid rooms format: expected dict, got %s", type(rooms).__name__)
        return []
        
    if not rooms:
        _LOGGER.warning("No rooms found, cannot parse controllers.")
        return []

    for room in rooms.values():
        # Validate room is a dict
        if not isinstance(room, dict):
            continue
            
        controller_id = room.get("controller")
        
        # Validate controller_id
        if not controller_id or not isinstance(controller_id, str):
            continue
        
        # We only add the controller once, using the first
        # room name we see as its "representative" name.
        if controller_id not in controllers:
            room_name = room.get("name", "Unknown Room")
            if not isinstance(room_name, str):
                room_name = "Unknown Room"
                
            controllers[controller_id] = {
                "id": controller_id,
                "room_name": room_name
            }
            
    return list(controllers.values())
