"""Certificate management and automatic rotation."""

import os
import logging
import datetime
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import subprocess
import json

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

# Handle platform-specific imports
try:
    import pwd
    import grp
    PWD_AVAILABLE = True
except ImportError:
    PWD_AVAILABLE = False

logger = logging.getLogger(__name__)


class CertificateManager:
    """Manages X.509 certificates and automatic rotation."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize certificate manager.
        
        Args:
            config: Certificate configuration dictionary
        """
        self.config = config or {}
        self.cert_dir = Path(self.config.get('cert_dir', '/etc/ssl/iot-ids'))
        self.ca_cert_path = self.cert_dir / 'ca.crt'
        self.ca_key_path = self.cert_dir / 'ca.key'
        self.rotation_threshold_days = self.config.get('rotation_threshold_days', 30)
        self.cert_validity_days = self.config.get('cert_validity_days', 365)
        
        # Ensure certificate directory exists
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        
    def create_ca_certificate(self, common_name: str = "IoT IDS CA") -> bool:
        """Create a Certificate Authority certificate.
        
        Args:
            common_name: Common name for the CA certificate
            
        Returns:
            True if CA certificate was created successfully
        """
        try:
            # Generate CA private key
            ca_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096
            )
            
            # Create CA certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IoT IDS"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])
            
            ca_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                ca_private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)  # 10 years for CA
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).sign(ca_private_key, hashes.SHA256())
            
            # Save CA certificate and private key
            with open(self.ca_cert_path, 'wb') as f:
                f.write(ca_cert.public_bytes(Encoding.PEM))
                
            with open(self.ca_key_path, 'wb') as f:
                f.write(ca_private_key.private_bytes(
                    Encoding.PEM,
                    PrivateFormat.PKCS8,
                    NoEncryption()
                ))
                
            # Set appropriate permissions
            os.chmod(self.ca_key_path, 0o600)
            os.chmod(self.ca_cert_path, 0o644)
            
            logger.info(f"Created CA certificate: {self.ca_cert_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create CA certificate: {e}")
            return False
            
    def create_server_certificate(self, common_name: str, 
                                san_list: Optional[List[str]] = None) -> Tuple[bool, Optional[str], Optional[str]]:
        """Create a server certificate signed by the CA.
        
        Args:
            common_name: Common name for the server certificate
            san_list: List of Subject Alternative Names
            
        Returns:
            Tuple of (success, cert_path, key_path)
        """
        try:
            if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
                logger.error("CA certificate or key not found")
                return False, None, None
                
            # Load CA certificate and key
            with open(self.ca_cert_path, 'rb') as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
                
            with open(self.ca_key_path, 'rb') as f:
                ca_private_key = serialization.load_pem_private_key(f.read(), password=None)
                
            # Generate server private key
            server_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Create server certificate
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IoT IDS"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])
            
            cert_builder = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                server_private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=self.cert_validity_days)
            )
            
            # Add Subject Alternative Names
            san_names = [x509.DNSName(common_name)]
            if san_list:
                for san in san_list:
                    if san.replace('.', '').isdigit():  # IP address
                        import ipaddress
                        san_names.append(x509.IPAddress(ipaddress.ip_address(san)))
                    else:  # DNS name
                        san_names.append(x509.DNSName(san))
                        
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(san_names),
                critical=False,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=True,
            )
            
            server_cert = cert_builder.sign(ca_private_key, hashes.SHA256())
            
            # Save server certificate and private key
            cert_path = self.cert_dir / f"{common_name}.crt"
            key_path = self.cert_dir / f"{common_name}.key"
            
            with open(cert_path, 'wb') as f:
                f.write(server_cert.public_bytes(Encoding.PEM))
                
            with open(key_path, 'wb') as f:
                f.write(server_private_key.private_bytes(
                    Encoding.PEM,
                    PrivateFormat.PKCS8,
                    NoEncryption()
                ))
                
            # Set appropriate permissions
            os.chmod(key_path, 0o600)
            os.chmod(cert_path, 0o644)
            
            logger.info(f"Created server certificate: {cert_path}")
            return True, str(cert_path), str(key_path)
            
        except Exception as e:
            logger.error(f"Failed to create server certificate: {e}")
            return False, None, None
            
    def check_certificate_expiry(self, cert_path: str) -> Optional[datetime.datetime]:
        """Check when a certificate expires.
        
        Args:
            cert_path: Path to the certificate file
            
        Returns:
            Expiry datetime or None if certificate cannot be read
        """
        try:
            with open(cert_path, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
                
            return cert.not_valid_after
            
        except Exception as e:
            logger.error(f"Failed to check certificate expiry for {cert_path}: {e}")
            return None
            
    def needs_rotation(self, cert_path: str) -> bool:
        """Check if a certificate needs rotation.
        
        Args:
            cert_path: Path to the certificate file
            
        Returns:
            True if certificate needs rotation
        """
        expiry = self.check_certificate_expiry(cert_path)
        if not expiry:
            return True  # Cannot read certificate, assume it needs rotation
            
        threshold = datetime.datetime.utcnow() + datetime.timedelta(days=self.rotation_threshold_days)
        return expiry <= threshold
        
    def rotate_certificate(self, common_name: str, san_list: Optional[List[str]] = None) -> bool:
        """Rotate a certificate by creating a new one.
        
        Args:
            common_name: Common name for the certificate
            san_list: List of Subject Alternative Names
            
        Returns:
            True if certificate was rotated successfully
        """
        try:
            cert_path = self.cert_dir / f"{common_name}.crt"
            
            # Backup old certificate if it exists
            if cert_path.exists():
                backup_path = cert_path.with_suffix(f".crt.backup.{int(datetime.datetime.utcnow().timestamp())}")
                cert_path.rename(backup_path)
                logger.info(f"Backed up old certificate to {backup_path}")
                
            # Create new certificate
            success, new_cert_path, new_key_path = self.create_server_certificate(common_name, san_list)
            
            if success:
                logger.info(f"Rotated certificate for {common_name}")
                return True
            else:
                logger.error(f"Failed to rotate certificate for {common_name}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to rotate certificate for {common_name}: {e}")
            return False
            
    def get_certificate_info(self, cert_path: str) -> Optional[Dict[str, Any]]:
        """Get information about a certificate.
        
        Args:
            cert_path: Path to the certificate file
            
        Returns:
            Dictionary with certificate information
        """
        try:
            with open(cert_path, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
                
            # Extract subject information
            subject_info = {}
            for attribute in cert.subject:
                subject_info[attribute.oid._name] = attribute.value
                
            # Extract SAN information
            san_list = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for san in san_ext.value:
                    san_list.append(str(san))
            except x509.ExtensionNotFound:
                pass
                
            return {
                'subject': subject_info,
                'issuer': {attr.oid._name: attr.value for attr in cert.issuer},
                'serial_number': str(cert.serial_number),
                'not_valid_before': cert.not_valid_before.isoformat(),
                'not_valid_after': cert.not_valid_after.isoformat(),
                'subject_alternative_names': san_list,
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'needs_rotation': self.needs_rotation(cert_path)
            }
            
        except Exception as e:
            logger.error(f"Failed to get certificate info for {cert_path}: {e}")
            return None
            
    def list_certificates(self) -> List[Dict[str, Any]]:
        """List all certificates in the certificate directory.
        
        Returns:
            List of certificate information dictionaries
        """
        certificates = []
        
        try:
            for cert_file in self.cert_dir.glob('*.crt'):
                if cert_file.name != 'ca.crt':  # Skip CA certificate
                    cert_info = self.get_certificate_info(str(cert_file))
                    if cert_info:
                        cert_info['file_path'] = str(cert_file)
                        certificates.append(cert_info)
                        
        except Exception as e:
            logger.error(f"Failed to list certificates: {e}")
            
        return certificates
        
    def auto_rotate_certificates(self) -> Dict[str, bool]:
        """Automatically rotate certificates that need rotation.
        
        Returns:
            Dictionary mapping certificate names to rotation success status
        """
        rotation_results = {}
        
        try:
            certificates = self.list_certificates()
            
            for cert_info in certificates:
                if cert_info.get('needs_rotation', False):
                    common_name = cert_info['subject'].get('commonName')
                    if common_name:
                        # Extract SAN list from certificate info
                        san_list = cert_info.get('subject_alternative_names', [])
                        # Filter out the common name from SAN list to avoid duplication
                        san_list = [san for san in san_list if san != common_name]
                        
                        success = self.rotate_certificate(common_name, san_list)
                        rotation_results[common_name] = success
                        
        except Exception as e:
            logger.error(f"Failed to auto-rotate certificates: {e}")
            
        return rotation_results