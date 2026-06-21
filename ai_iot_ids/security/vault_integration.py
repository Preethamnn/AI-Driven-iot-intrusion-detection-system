"""HashiCorp Vault integration for secure secret storage."""

import os
import logging
import json
from typing import Dict, List, Optional, Any, Union
import requests
from pathlib import Path

logger = logging.getLogger(__name__)


class VaultClient:
    """HashiCorp Vault client for secure secret management."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Vault client.
        
        Args:
            config: Vault configuration dictionary
        """
        self.config = config or {}
        self.vault_url = self.config.get('vault_url', 'http://localhost:8200')
        self.vault_token = self.config.get('vault_token') or os.getenv('VAULT_TOKEN')
        self.vault_namespace = self.config.get('vault_namespace')
        self.mount_point = self.config.get('mount_point', 'secret')
        self.timeout = self.config.get('timeout', 30)
        
        # Set up session with common headers
        self.session = requests.Session()
        if self.vault_token:
            self.session.headers.update({'X-Vault-Token': self.vault_token})
        if self.vault_namespace:
            self.session.headers.update({'X-Vault-Namespace': self.vault_namespace})
            
    def authenticate_with_approle(self, role_id: str, secret_id: str) -> bool:
        """Authenticate with Vault using AppRole method.
        
        Args:
            role_id: AppRole role ID
            secret_id: AppRole secret ID
            
        Returns:
            True if authentication was successful
        """
        try:
            auth_data = {
                'role_id': role_id,
                'secret_id': secret_id
            }
            
            response = self.session.post(
                f"{self.vault_url}/v1/auth/approle/login",
                json=auth_data,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            auth_response = response.json()
            self.vault_token = auth_response['auth']['client_token']
            self.session.headers.update({'X-Vault-Token': self.vault_token})
            
            logger.info("Successfully authenticated with Vault using AppRole")
            return True
            
        except Exception as e:
            logger.error(f"Failed to authenticate with Vault: {e}")
            return False
            
    def authenticate_with_kubernetes(self, service_account_token_path: str, role: str) -> bool:
        """Authenticate with Vault using Kubernetes method.
        
        Args:
            service_account_token_path: Path to Kubernetes service account token
            role: Vault Kubernetes role name
            
        Returns:
            True if authentication was successful
        """
        try:
            # Read service account token
            with open(service_account_token_path, 'r') as f:
                jwt_token = f.read().strip()
                
            auth_data = {
                'jwt': jwt_token,
                'role': role
            }
            
            response = self.session.post(
                f"{self.vault_url}/v1/auth/kubernetes/login",
                json=auth_data,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            auth_response = response.json()
            self.vault_token = auth_response['auth']['client_token']
            self.session.headers.update({'X-Vault-Token': self.vault_token})
            
            logger.info("Successfully authenticated with Vault using Kubernetes")
            return True
            
        except Exception as e:
            logger.error(f"Failed to authenticate with Vault using Kubernetes: {e}")
            return False
            
    def store_secret(self, path: str, secret_data: Dict[str, Any]) -> bool:
        """Store a secret in Vault.
        
        Args:
            path: Secret path in Vault
            secret_data: Dictionary containing secret data
            
        Returns:
            True if secret was stored successfully
        """
        try:
            # For KV v2, wrap data in 'data' field
            if self._is_kv_v2():
                payload = {'data': secret_data}
                url = f"{self.vault_url}/v1/{self.mount_point}/data/{path}"
            else:
                payload = secret_data
                url = f"{self.vault_url}/v1/{self.mount_point}/{path}"
                
            response = self.session.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            
            logger.info(f"Successfully stored secret at path: {path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store secret at path {path}: {e}")
            return False
            
    def retrieve_secret(self, path: str) -> Optional[Dict[str, Any]]:
        """Retrieve a secret from Vault.
        
        Args:
            path: Secret path in Vault
            
        Returns:
            Dictionary containing secret data or None if not found
        """
        try:
            if self._is_kv_v2():
                url = f"{self.vault_url}/v1/{self.mount_point}/data/{path}"
            else:
                url = f"{self.vault_url}/v1/{self.mount_point}/{path}"
                
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            secret_response = response.json()
            
            if self._is_kv_v2():
                return secret_response['data']['data']
            else:
                return secret_response['data']
                
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"Secret not found at path: {path}")
            else:
                logger.error(f"Failed to retrieve secret at path {path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve secret at path {path}: {e}")
            return None
            
    def delete_secret(self, path: str) -> bool:
        """Delete a secret from Vault.
        
        Args:
            path: Secret path in Vault
            
        Returns:
            True if secret was deleted successfully
        """
        try:
            if self._is_kv_v2():
                url = f"{self.vault_url}/v1/{self.mount_point}/data/{path}"
            else:
                url = f"{self.vault_url}/v1/{self.mount_point}/{path}"
                
            response = self.session.delete(url, timeout=self.timeout)
            response.raise_for_status()
            
            logger.info(f"Successfully deleted secret at path: {path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete secret at path {path}: {e}")
            return False
            
    def list_secrets(self, path: str = "") -> Optional[List[str]]:
        """List secrets at a given path.
        
        Args:
            path: Path to list secrets from
            
        Returns:
            List of secret names or None if listing failed
        """
        try:
            if self._is_kv_v2():
                url = f"{self.vault_url}/v1/{self.mount_point}/metadata/{path}"
            else:
                url = f"{self.vault_url}/v1/{self.mount_point}/{path}"
                
            response = self.session.request('LIST', url, timeout=self.timeout)
            response.raise_for_status()
            
            list_response = response.json()
            return list_response['data']['keys']
            
        except Exception as e:
            logger.error(f"Failed to list secrets at path {path}: {e}")
            return None
            
    def create_database_credentials(self, db_role: str) -> Optional[Dict[str, str]]:
        """Generate dynamic database credentials.
        
        Args:
            db_role: Database role name configured in Vault
            
        Returns:
            Dictionary with username and password or None if failed
        """
        try:
            url = f"{self.vault_url}/v1/database/creds/{db_role}"
            
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            creds_response = response.json()
            return {
                'username': creds_response['data']['username'],
                'password': creds_response['data']['password']
            }
            
        except Exception as e:
            logger.error(f"Failed to create database credentials for role {db_role}: {e}")
            return None
            
    def renew_token(self, increment: Optional[int] = None) -> bool:
        """Renew the current Vault token.
        
        Args:
            increment: Token TTL increment in seconds
            
        Returns:
            True if token was renewed successfully
        """
        try:
            payload = {}
            if increment:
                payload['increment'] = increment
                
            response = self.session.post(
                f"{self.vault_url}/v1/auth/token/renew-self",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            logger.info("Successfully renewed Vault token")
            return True
            
        except Exception as e:
            logger.error(f"Failed to renew Vault token: {e}")
            return False
            
    def get_token_info(self) -> Optional[Dict[str, Any]]:
        """Get information about the current token.
        
        Returns:
            Dictionary with token information or None if failed
        """
        try:
            response = self.session.get(
                f"{self.vault_url}/v1/auth/token/lookup-self",
                timeout=self.timeout
            )
            response.raise_for_status()
            
            return response.json()['data']
            
        except Exception as e:
            logger.error(f"Failed to get token info: {e}")
            return None
            
    def is_authenticated(self) -> bool:
        """Check if the client is authenticated with Vault.
        
        Returns:
            True if authenticated
        """
        try:
            token_info = self.get_token_info()
            return token_info is not None
        except Exception:
            return False
            
    def _is_kv_v2(self) -> bool:
        """Check if the mount point is using KV v2 engine.
        
        Returns:
            True if using KV v2
        """
        try:
            response = self.session.get(
                f"{self.vault_url}/v1/sys/mounts/{self.mount_point}",
                timeout=self.timeout
            )
            response.raise_for_status()
            
            mount_info = response.json()
            return mount_info['data']['type'] == 'kv' and mount_info['data']['options'].get('version') == '2'
            
        except Exception:
            # Default to KV v1 if we can't determine
            return False


class SecretManager:
    """High-level secret management interface."""
    
    def __init__(self, vault_client: VaultClient):
        """Initialize secret manager.
        
        Args:
            vault_client: Configured Vault client instance
        """
        self.vault = vault_client
        self.secret_cache = {}
        self.cache_ttl = 300  # 5 minutes
        
    def get_database_config(self, service_name: str) -> Optional[Dict[str, str]]:
        """Get database configuration for a service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            Database configuration dictionary
        """
        secret_path = f"database/{service_name}"
        return self.vault.retrieve_secret(secret_path)
        
    def get_api_keys(self, service_name: str) -> Optional[Dict[str, str]]:
        """Get API keys for a service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            API keys dictionary
        """
        secret_path = f"api-keys/{service_name}"
        return self.vault.retrieve_secret(secret_path)
        
    def get_tls_certificates(self, service_name: str) -> Optional[Dict[str, str]]:
        """Get TLS certificates for a service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            TLS certificate data dictionary
        """
        secret_path = f"tls/{service_name}"
        return self.vault.retrieve_secret(secret_path)
        
    def store_service_config(self, service_name: str, config_data: Dict[str, Any]) -> bool:
        """Store configuration for a service.
        
        Args:
            service_name: Name of the service
            config_data: Configuration data to store
            
        Returns:
            True if configuration was stored successfully
        """
        secret_path = f"config/{service_name}"
        return self.vault.store_secret(secret_path, config_data)
        
    def rotate_api_key(self, service_name: str, key_name: str, new_key: str) -> bool:
        """Rotate an API key for a service.
        
        Args:
            service_name: Name of the service
            key_name: Name of the API key
            new_key: New API key value
            
        Returns:
            True if API key was rotated successfully
        """
        try:
            # Get existing API keys
            secret_path = f"api-keys/{service_name}"
            existing_keys = self.vault.retrieve_secret(secret_path) or {}
            
            # Update the specific key
            existing_keys[key_name] = new_key
            
            # Store updated keys
            return self.vault.store_secret(secret_path, existing_keys)
            
        except Exception as e:
            logger.error(f"Failed to rotate API key {key_name} for {service_name}: {e}")
            return False
            
    def get_encryption_keys(self, service_name: str) -> Optional[Dict[str, str]]:
        """Get encryption keys for a service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            Encryption keys dictionary
        """
        secret_path = f"encryption/{service_name}"
        return self.vault.retrieve_secret(secret_path)
        
    def store_encryption_keys(self, service_name: str, keys: Dict[str, str]) -> bool:
        """Store encryption keys for a service.
        
        Args:
            service_name: Name of the service
            keys: Encryption keys to store
            
        Returns:
            True if keys were stored successfully
        """
        secret_path = f"encryption/{service_name}"
        return self.vault.store_secret(secret_path, keys)