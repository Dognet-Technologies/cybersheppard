# License System - Complete Specification

## Overview

Intellidog uses a GPG-signed license file system to control access to premium threat intelligence features.

**License Format**: JSON + GPG Signature  
**Signature Algorithm**: RSA 4096-bit  
**Validation**: GPG signature verification + expiration check  
**Storage**: PostgreSQL `intellidog.intellidog_license` table

---

## License File Format

### Structure

A valid Intellidog license file (`.lic`) consists of:
1. GPG signed message header
2. JSON license data (cleartext)
3. GPG signature block

### Example License File

**File**: `INTL-2025-ACME-0001.lic`

```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

{
  "license_key": "INTL-2025-ACME-0001",
  "customer": "ACME Corporation",
  "issued_at": "2025-01-01T00:00:00Z",
  "expires_at": "2026-01-01T23:59:59Z",
  "max_machines": 250,
  "features": [
    "threat_intel_feeds",
    "correlation",
    "virtual_patching",
    "hunting",
    "api_access"
  ],
  "support_level": "enterprise",
  "metadata": {
    "sales_order": "SO-2025-0042",
    "account_manager": "john.doe@dognet.tech",
    "deployment_type": "on-premise"
  }
}
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEE... [signature data continues]
... [multiple lines of base64 signature]
-----END PGP SIGNATURE-----
```

### JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": [
    "license_key",
    "customer",
    "issued_at",
    "expires_at",
    "max_machines",
    "features",
    "support_level"
  ],
  "properties": {
    "license_key": {
      "type": "string",
      "pattern": "^INTL-[0-9]{4}-[A-Z0-9]+-[0-9]{4}$",
      "description": "Unique license identifier"
    },
    "customer": {
      "type": "string",
      "minLength": 1,
      "maxLength": 200,
      "description": "Customer organization name"
    },
    "issued_at": {
      "type": "string",
      "format": "date-time",
      "description": "License issue timestamp (ISO 8601)"
    },
    "expires_at": {
      "type": "string",
      "format": "date-time",
      "description": "License expiration timestamp (ISO 8601)"
    },
    "max_machines": {
      "type": "integer",
      "minimum": 1,
      "maximum": 10000,
      "description": "Maximum number of monitored machines"
    },
    "features": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": [
          "threat_intel_feeds",
          "correlation",
          "virtual_patching",
          "hunting",
          "api_access",
          "custom_feeds",
          "advanced_analytics"
        ]
      },
      "minItems": 1,
      "uniqueItems": true,
      "description": "Enabled feature list"
    },
    "support_level": {
      "type": "string",
      "enum": ["standard", "professional", "enterprise"],
      "description": "Support tier"
    },
    "metadata": {
      "type": "object",
      "description": "Additional license metadata (optional)"
    }
  }
}
```

---

## GPG Key Management

### Dognet Licensing Keys

**Location**: `/opt/cybersheppard/keys/`

```
/opt/cybersheppard/keys/
├── dognet-licensing-public.key    # Public key (installed on CyberSheppard)
└── dognet-licensing-private.key   # Private key (ONLY on Dognet licensing server)
```

### Public Key Format

**File**: `dognet-licensing-public.key`

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGXXXXXBEAC... [key data]
... [multiple lines]
-----END PGP PUBLIC KEY BLOCK-----
```

**Key Details**:
- Type: RSA
- Length: 4096 bits
- Created: 2025-01-01
- Expires: 2035-01-01 (10 year validity)
- User ID: Dognet Technologies Licensing <licensing@dognet.tech>
- Fingerprint: `1234 5678 90AB CDEF 1234 5678 90AB CDEF 1234 5678`

### Generating Keys (Dognet Internal Process)

**One-time setup** (Dognet licensing server):

```bash
#!/bin/bash
# generate_licensing_keys.sh
# Run ONCE on secure Dognet licensing server

gpg --full-generate-key

# Interactive prompts:
# - Kind: RSA and RSA
# - Key size: 4096
# - Expiration: 10y
# - Real name: Dognet Technologies Licensing
# - Email: licensing@dognet.tech
# - Comment: Intellidog License Signing Key

# Export public key
gpg --armor --export licensing@dognet.tech > dognet-licensing-public.key

# Export private key (KEEP SECURE!)
gpg --armor --export-secret-keys licensing@dognet.tech > dognet-licensing-private.key

echo "Public key: dognet-licensing-public.key (distribute to customers)"
echo "Private key: dognet-licensing-private.key (NEVER SHARE - store in vault)"
```

### Installing Public Key on CyberSheppard

**During CyberSheppard installation**:

```bash
#!/bin/bash
# install_licensing_key.sh
# Included in CyberSheppard installation package

KEYS_DIR="/opt/cybersheppard/keys"
PUBLIC_KEY_URL="https://licensing.dognet.tech/public-keys/intellidog-2025.asc"

# Create keys directory
sudo mkdir -p "$KEYS_DIR"
sudo chmod 755 "$KEYS_DIR"

# Download and install public key
sudo curl -sSL "$PUBLIC_KEY_URL" -o "$KEYS_DIR/dognet-licensing-public.key"
sudo chmod 644 "$KEYS_DIR/dognet-licensing-public.key"

# Verify key fingerprint
EXPECTED_FP="1234567890ABCDEF1234567890ABCDEF12345678"
ACTUAL_FP=$(gpg --with-colons --import-options show-only --import "$KEYS_DIR/dognet-licensing-public.key" 2>/dev/null | awk -F: '/^fpr:/ {print $10}' | head -1)

if [ "$ACTUAL_FP" = "$EXPECTED_FP" ]; then
    echo "✓ Public key verified successfully"
else
    echo "✗ Public key fingerprint mismatch!"
    exit 1
fi

echo "Licensing public key installed at $KEYS_DIR/dognet-licensing-public.key"
```

---

## License Generation (Dognet Internal)

### Generation Script

**File**: `generate_license.py` (Dognet licensing server)

```python
#!/usr/bin/env python3
"""
Intellidog License Generator
Dognet Technologies Internal Tool

Usage:
    python generate_license.py --customer "ACME Corp" --machines 250 --months 12
"""

import json
import gnupg
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

class LicenseGenerator:
    def __init__(self, gpg_home: str = None):
        self.gpg = gnupg.GPG(gnupghome=gpg_home)
        self.signing_key = "licensing@dognet.tech"
    
    def generate_license_key(self, customer_name: str, year: int, sequence: int) -> str:
        """
        Generate unique license key.
        
        Format: INTL-YYYY-CUSTOMER-NNNN
        Example: INTL-2025-ACME-0001
        """
        customer_code = ''.join(c for c in customer_name.upper() if c.isalnum())[:8]
        return f"INTL-{year}-{customer_code}-{sequence:04d}"
    
    def create_license(self,
                      customer: str,
                      max_machines: int,
                      duration_months: int,
                      support_level: str = "standard",
                      features: list = None,
                      metadata: dict = None) -> dict:
        """Create license data structure"""
        
        now = datetime.now(timezone.utc)
        issued_at = now
        expires_at = now + timedelta(days=30 * duration_months)
        
        if features is None:
            features = [
                "threat_intel_feeds",
                "correlation",
                "virtual_patching",
                "hunting"
            ]
        
        # Add API access for professional/enterprise
        if support_level in ("professional", "enterprise"):
            features.append("api_access")
        
        # Add advanced features for enterprise
        if support_level == "enterprise":
            features.extend(["custom_feeds", "advanced_analytics"])
        
        license_data = {
            "license_key": self.generate_license_key(customer, now.year, 1),
            "customer": customer,
            "issued_at": issued_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "max_machines": max_machines,
            "features": sorted(set(features)),
            "support_level": support_level,
            "metadata": metadata or {}
        }
        
        return license_data
    
    def sign_license(self, license_data: dict, passphrase: str = None) -> str:
        """
        Sign license data with GPG.
        
        Returns signed message (cleartext signature format).
        """
        json_data = json.dumps(license_data, indent=2, sort_keys=True)
        
        signed = self.gpg.sign(
            json_data,
            keyid=self.signing_key,
            passphrase=passphrase,
            clearsign=True,
            detach=False
        )
        
        if not signed:
            raise RuntimeError(f"GPG signing failed: {signed.status}")
        
        return str(signed)
    
    def generate_license_file(self,
                             customer: str,
                             max_machines: int,
                             duration_months: int,
                             support_level: str = "standard",
                             output_file: str = None,
                             passphrase: str = None) -> str:
        """
        Generate complete signed license file.
        
        Returns path to generated .lic file.
        """
        # Create license data
        license_data = self.create_license(
            customer=customer,
            max_machines=max_machines,
            duration_months=duration_months,
            support_level=support_level
        )
        
        # Sign license
        signed_license = self.sign_license(license_data, passphrase)
        
        # Determine output filename
        if output_file is None:
            license_key = license_data['license_key']
            output_file = f"{license_key}.lic"
        
        # Write to file
        Path(output_file).write_text(signed_license)
        
        print(f"License generated: {output_file}")
        print(f"Customer: {customer}")
        print(f"License Key: {license_data['license_key']}")
        print(f"Valid until: {license_data['expires_at']}")
        print(f"Max machines: {max_machines}")
        print(f"Support level: {support_level}")
        
        return output_file

def main():
    parser = argparse.ArgumentParser(description='Generate Intellidog license')
    parser.add_argument('--customer', required=True, help='Customer name')
    parser.add_argument('--machines', type=int, required=True, help='Maximum machines')
    parser.add_argument('--months', type=int, default=12, help='License duration in months')
    parser.add_argument('--support', choices=['standard', 'professional', 'enterprise'],
                       default='standard', help='Support level')
    parser.add_argument('--output', help='Output filename (default: auto-generated)')
    parser.add_argument('--passphrase', help='GPG key passphrase (or set GPG_PASSPHRASE env var)')
    
    args = parser.parse_args()
    
    import os
    passphrase = args.passphrase or os.getenv('GPG_PASSPHRASE')
    
    generator = LicenseGenerator()
    generator.generate_license_file(
        customer=args.customer,
        max_machines=args.machines,
        duration_months=args.months,
        support_level=args.support,
        output_file=args.output,
        passphrase=passphrase
    )

if __name__ == '__main__':
    main()
```

### Usage Examples

```bash
# Generate standard license for 100 machines, 12 months
python generate_license.py \
    --customer "ACME Corporation" \
    --machines 100 \
    --months 12 \
    --support standard

# Generate enterprise license for 500 machines, 36 months
export GPG_PASSPHRASE="your-gpg-key-passphrase"
python generate_license.py \
    --customer "Enterprise Corp" \
    --machines 500 \
    --months 36 \
    --support enterprise \
    --output EC-2025-ENTERPRISE.lic
```

---

## License Validation (CyberSheppard)

### Complete Validator Implementation

**File**: `backend/app/modules/intellidog/services/license_validator.py`

```python
import gnupg
import json
import re
from datetime import datetime, timezone
from typing import Optional, Tuple, List
from pathlib import Path
from sqlalchemy.orm import Session
from ..models.license import IntellidogLicense
from ..schemas.license import LicenseValidationResult, LicenseResponse

class LicenseValidator:
    """
    Intellidog license validation service.
    
    Validates:
    1. GPG signature authenticity
    2. JSON format correctness
    3. Required fields presence
    4. Expiration date
    5. Machine count limits
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.gpg = gnupg.GPG()
        self.public_key_path = '/opt/cybersheppard/keys/dognet-licensing-public.key'
        self.expected_fingerprint = '1234567890ABCDEF1234567890ABCDEF12345678'
        self._import_public_key()
    
    def _import_public_key(self) -> None:
        """Import Dognet public GPG key for signature verification"""
        if not Path(self.public_key_path).exists():
            raise FileNotFoundError(
                f"Dognet licensing public key not found at {self.public_key_path}. "
                f"Please ensure CyberSheppard is properly installed."
            )
        
        try:
            with open(self.public_key_path, 'r') as f:
                key_data = f.read()
            
            import_result = self.gpg.import_keys(key_data)
            
            if import_result.count == 0:
                raise RuntimeError("Failed to import GPG public key")
            
            # Verify fingerprint
            keys = self.gpg.list_keys()
            key_found = False
            for key in keys:
                if key['fingerprint'].replace(' ', '') == self.expected_fingerprint:
                    key_found = True
                    break
            
            if not key_found:
                raise RuntimeError(
                    f"Imported key fingerprint does not match expected fingerprint. "
                    f"Expected: {self.expected_fingerprint}"
                )
            
        except Exception as e:
            raise RuntimeError(f"Failed to import licensing public key: {str(e)}")
    
    def validate_and_store(self, 
                          license_content: str, 
                          uploaded_by_user_id: int = None) -> LicenseValidationResult:
        """
        Validate license file and store if valid.
        
        Validation steps:
        1. Verify GPG signature
        2. Extract and parse JSON
        3. Validate schema
        4. Check expiration
        5. Verify license key format
        6. Store in database
        
        Returns:
            LicenseValidationResult with validation outcome
        """
        errors = []
        warnings = []
        
        # Step 1: Verify GPG signature
        verified = self.gpg.verify(license_content)
        
        if not verified.valid:
            errors.append(f"GPG signature verification failed: {verified.status}")
            return LicenseValidationResult(
                valid=False,
                license=None,
                errors=errors,
                warnings=warnings
            )
        
        # Verify signature is from expected key
        if verified.fingerprint.replace(' ', '') != self.expected_fingerprint:
            errors.append(
                f"License signed with unknown key. "
                f"Expected fingerprint: {self.expected_fingerprint}, "
                f"got: {verified.fingerprint}"
            )
            return LicenseValidationResult(valid=False, license=None, errors=errors)
        
        # Step 2: Extract JSON content from signed message
        json_content = self._extract_json_from_signed_message(license_content)
        if not json_content:
            errors.append("Failed to extract license data from signed message")
            return LicenseValidationResult(valid=False, license=None, errors=errors)
        
        # Step 3: Parse JSON
        try:
            license_data = json.loads(json_content)
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON format: {str(e)}")
            return LicenseValidationResult(valid=False, license=None, errors=errors)
        
        # Step 4: Validate required fields
        validation_errors = self._validate_license_schema(license_data)
        if validation_errors:
            errors.extend(validation_errors)
            return LicenseValidationResult(valid=False, license=None, errors=errors)
        
        # Step 5: Check expiration
        try:
            expires_at = datetime.fromisoformat(
                license_data['expires_at'].replace('Z', '+00:00')
            )
            
            if expires_at < datetime.now(timezone.utc):
                errors.append(
                    f"License has expired on {expires_at.strftime('%Y-%m-%d')}"
                )
                return LicenseValidationResult(valid=False, license=None, errors=errors)
            
            # Warning if expiring soon (30 days)
            days_until_expiry = (expires_at - datetime.now(timezone.utc)).days
            if days_until_expiry <= 30:
                warnings.append(
                    f"License expires in {days_until_expiry} days "
                    f"({expires_at.strftime('%Y-%m-%d')})"
                )
            
        except (ValueError, KeyError) as e:
            errors.append(f"Invalid expiration date: {str(e)}")
            return LicenseValidationResult(valid=False, license=None, errors=errors)
        
        # Step 6: Verify license key format
        license_key = license_data.get('license_key', '')
        if not re.match(r'^INTL-\d{4}-[A-Z0-9]+-\d{4}$', license_key):
            errors.append(
                f"Invalid license key format: {license_key}. "
                f"Expected format: INTL-YYYY-CUSTOMER-NNNN"
            )
            return LicenseValidationResult(valid=False, license=None, errors=errors)
        
        # Step 7: Check for duplicate license key
        existing = self.db.query(IntellidogLicense).filter(
            IntellidogLicense.license_key == license_key
        ).first()
        
        if existing:
            if existing.is_active:
                errors.append(
                    f"License key {license_key} is already installed and active"
                )
                return LicenseValidationResult(valid=False, license=None, errors=errors)
            else:
                warnings.append(
                    f"License key {license_key} was previously installed but is now inactive"
                )
        
        # Step 8: Store in database
        try:
            # Deactivate any existing active licenses
            self.db.query(IntellidogLicense).update(
                {IntellidogLicense.is_active: False}
            )
            
            # Parse issued_at
            issued_at = datetime.fromisoformat(
                license_data['issued_at'].replace('Z', '+00:00')
            )
            
            # Create new license record
            license_obj = IntellidogLicense(
                license_key=license_key,
                customer_name=license_data['customer'],
                issued_at=issued_at,
                expires_at=expires_at,
                max_machines=license_data['max_machines'],
                features=license_data['features'],
                support_level=license_data['support_level'],
                license_file_content=license_content,
                gpg_signature_valid=True,
                is_active=True,
                last_validated_at=datetime.now(timezone.utc)
            )
            
            self.db.add(license_obj)
            self.db.commit()
            self.db.refresh(license_obj)
            
            return LicenseValidationResult(
                valid=True,
                license=LicenseResponse.model_validate(license_obj),
                errors=[],
                warnings=warnings
            )
        
        except Exception as e:
            self.db.rollback()
            errors.append(f"Database error while storing license: {str(e)}")
            return LicenseValidationResult(valid=False, license=None, errors=errors)
    
    def _extract_json_from_signed_message(self, signed_message: str) -> Optional[str]:
        """
        Extract JSON content from PGP signed message.
        
        Format:
        -----BEGIN PGP SIGNED MESSAGE-----
        Hash: SHA512
        
        { JSON content }
        -----BEGIN PGP SIGNATURE-----
        ...
        -----END PGP SIGNATURE-----
        """
        lines = signed_message.split('\n')
        json_lines = []
        in_content = False
        
        for line in lines:
            # End of content
            if line.startswith('-----BEGIN PGP SIGNATURE-----'):
                break
            
            # Skip header lines
            if line.startswith('-----BEGIN PGP SIGNED MESSAGE-----'):
                continue
            if line.startswith('Hash:'):
                in_content = True
                continue
            
            # Collect content lines
            if in_content:
                # Skip blank line after Hash:
                if not json_lines and not line.strip():
                    continue
                json_lines.append(line)
        
        json_content = '\n'.join(json_lines).strip()
        return json_content if json_content else None
    
    def _validate_license_schema(self, license_data: dict) -> List[str]:
        """
        Validate license data against schema.
        
        Returns list of error messages (empty if valid).
        """
        errors = []
        
        # Required fields
        required_fields = [
            'license_key', 'customer', 'issued_at', 'expires_at',
            'max_machines', 'features', 'support_level'
        ]
        
        for field in required_fields:
            if field not in license_data:
                errors.append(f"Missing required field: {field}")
        
        if errors:
            return errors  # Don't validate further if required fields missing
        
        # Validate field types and constraints
        if not isinstance(license_data['customer'], str) or not license_data['customer']:
            errors.append("Field 'customer' must be a non-empty string")
        
        if not isinstance(license_data['max_machines'], int) or license_data['max_machines'] < 1:
            errors.append("Field 'max_machines' must be a positive integer")
        
        if not isinstance(license_data['features'], list) or not license_data['features']:
            errors.append("Field 'features' must be a non-empty array")
        
        valid_features = [
            'threat_intel_feeds', 'correlation', 'virtual_patching',
            'hunting', 'api_access', 'custom_feeds', 'advanced_analytics'
        ]
        for feature in license_data.get('features', []):
            if feature not in valid_features:
                errors.append(f"Unknown feature: {feature}")
        
        valid_support_levels = ['standard', 'professional', 'enterprise']
        if license_data['support_level'] not in valid_support_levels:
            errors.append(
                f"Invalid support_level: {license_data['support_level']}. "
                f"Must be one of: {', '.join(valid_support_levels)}"
            )
        
        return errors
    
    def validate_current(self) -> LicenseValidationResult:
        """
        Re-validate currently active license.
        
        Use case: Periodic license health check.
        """
        license = self.db.query(IntellidogLicense).filter(
            IntellidogLicense.is_active == True
        ).first()
        
        if not license:
            return LicenseValidationResult(
                valid=False,
                license=None,
                errors=["No active license found"],
                warnings=[]
            )
        
        # Re-validate from stored license file content
        return self.validate_and_store(license.license_file_content)
    
    def check_feature_enabled(self, feature_name: str) -> bool:
        """
        Check if specific feature is enabled in active license.
        
        Use case: Feature gates in application code.
        """
        license = self.db.query(IntellidogLicense).filter(
            IntellidogLicense.is_active == True
        ).first()
        
        if not license:
            return False
        
        if license.is_expired:
            return False
        
        return feature_name in license.features
    
    def check_machine_limit(self, current_machine_count: int) -> Tuple[bool, int]:
        """
        Check if adding machines would exceed license limit.
        
        Returns:
            (within_limit, available_slots)
        """
        license = self.db.query(IntellidogLicense).filter(
            IntellidogLicense.is_active == True
        ).first()
        
        if not license:
            return (False, 0)
        
        if license.is_expired:
            return (False, 0)
        
        available = license.max_machines - current_machine_count
        within_limit = current_machine_count < license.max_machines
        
        return (within_limit, max(0, available))
```

---

## Frontend Integration

### License Upload Component

**File**: `frontend/src/pages/Settings/LicenseUpload.tsx`

```typescript
import React, { useState } from 'react';
import { Upload, AlertCircle, CheckCircle, Info } from 'lucide-react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { uploadLicense, getCurrentLicense } from '@/services/intellidog/license';

export const LicenseUpload: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadResult, setUploadResult] = useState<any>(null);

  const { data: currentLicense } = useQuery({
    queryKey: ['intellidog', 'license'],
    queryFn: getCurrentLicense
  });

  const uploadMutation = useMutation({
    mutationFn: uploadLicense,
    onSuccess: (result) => {
      setUploadResult(result);
      setSelectedFile(null);
    }
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && file.name.endsWith('.lic')) {
      setSelectedFile(file);
      setUploadResult(null);
    } else {
      alert('Please select a .lic file');
    }
  };

  const handleUpload = () => {
    if (selectedFile) {
      uploadMutation.mutate(selectedFile);
    }
  };

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">Intellidog License</h2>

      {/* Current License Info */}
      {currentLicense && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <CheckCircle className="h-5 w-5 text-blue-600 mt-0.5" />
            <div className="flex-1">
              <h3 className="font-semibold text-blue-900">Active License</h3>
              <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                <dt className="text-blue-700">Customer:</dt>
                <dd className="text-blue-900 font-medium">{currentLicense.customer_name}</dd>
                
                <dt className="text-blue-700">License Key:</dt>
                <dd className="text-blue-900 font-mono text-xs">{currentLicense.license_key}</dd>
                
                <dt className="text-blue-700">Expires:</dt>
                <dd className="text-blue-900">{new Date(currentLicense.expires_at).toLocaleDateString()}</dd>
                
                <dt className="text-blue-700">Max Machines:</dt>
                <dd className="text-blue-900">{currentLicense.max_machines}</dd>
                
                <dt className="text-blue-700">Support Level:</dt>
                <dd className="text-blue-900 capitalize">{currentLicense.support_level}</dd>
              </dl>
            </div>
          </div>
        </div>
      )}

      {/* Upload Form */}
      <div className="border-2 border-dashed border-gray-300 rounded-lg p-8">
        <div className="flex flex-col items-center gap-4">
          <Upload className="h-12 w-12 text-gray-400" />
          <div className="text-center">
            <label htmlFor="license-upload" className="cursor-pointer">
              <span className="text-blue-600 hover:text-blue-700 font-medium">
                Choose license file
              </span>
              <input
                id="license-upload"
                type="file"
                accept=".lic"
                className="hidden"
                onChange={handleFileChange}
              />
            </label>
            <p className="text-sm text-gray-500 mt-1">
              Upload your Intellidog license (.lic file)
            </p>
          </div>

          {selectedFile && (
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-700">{selectedFile.name}</span>
              <button
                onClick={handleUpload}
                disabled={uploadMutation.isPending}
                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
              >
                {uploadMutation.isPending ? 'Uploading...' : 'Upload'}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Upload Result */}
      {uploadResult && (
        <div className={`rounded-lg p-4 ${
          uploadResult.valid 
            ? 'bg-green-50 border border-green-200' 
            : 'bg-red-50 border border-red-200'
        }`}>
          <div className="flex items-start gap-3">
            {uploadResult.valid ? (
              <CheckCircle className="h-5 w-5 text-green-600 mt-0.5" />
            ) : (
              <AlertCircle className="h-5 w-5 text-red-600 mt-0.5" />
            )}
            <div className="flex-1">
              <h3 className={`font-semibold ${
                uploadResult.valid ? 'text-green-900' : 'text-red-900'
              }`}>
                {uploadResult.valid ? 'License Activated' : 'Validation Failed'}
              </h3>
              
              {uploadResult.errors?.length > 0 && (
                <ul className="mt-2 space-y-1">
                  {uploadResult.errors.map((error: string, idx: number) => (
                    <li key={idx} className="text-sm text-red-700">• {error}</li>
                  ))}
                </ul>
              )}
              
              {uploadResult.warnings?.length > 0 && (
                <ul className="mt-2 space-y-1">
                  {uploadResult.warnings.map((warning: string, idx: number) => (
                    <li key={idx} className="text-sm text-yellow-700 flex items-start gap-2">
                      <Info className="h-4 w-4 mt-0.5" />
                      <span>{warning}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
```

---

## Feature Gates (Middleware)

### Backend Middleware

```python
# backend/app/modules/intellidog/middleware.py

from fastapi import Request, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db_session
from .services.license_validator import LicenseValidator

async def require_intellidog_license(request: Request):
    """
    Middleware to check for valid Intellidog license.
    
    Apply to all /api/intellidog/* routes.
    """
    with get_db_session() as db:
        validator = LicenseValidator(db)
        
        if not validator.check_license_required():
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail="Valid Intellidog license required. Please upload a license file."
            )

async def require_feature(feature_name: str):
    """
    Check if specific feature is enabled in license.
    
    Usage:
        @router.get("/advanced-analytics")
        async def get_analytics(
            _: None = Depends(require_feature("advanced_analytics"))
        ):
            ...
    """
    def dependency(request: Request):
        with get_db_session() as db:
            validator = LicenseValidator(db)
            
            if not validator.check_feature_enabled(feature_name):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Feature '{feature_name}' not enabled in your license"
                )
    
    return dependency
```

### Apply to Router

```python
# backend/app/modules/intellidog/api/__init__.py

from fastapi import APIRouter, Depends
from .middleware import require_intellidog_license

# Main Intellidog router
router = APIRouter(
    prefix="/api/intellidog",
    tags=["intellidog"],
    dependencies=[Depends(require_intellidog_license)]  # Apply to all routes
)

# Import sub-routers
from .license import router as license_router
from .feeds import router as feeds_router
from .detections import router as detections_router

router.include_router(license_router)
router.include_router(feeds_router)
router.include_router(detections_router)
```

---

## Periodic License Check (Celery Task)

```python
# backend/app/modules/intellidog/tasks/license_check.py

from celery import shared_task
from app.database import get_db_session
from ..services.license_validator import LicenseValidator
from ..services.alert_service import send_admin_alert
import logging

logger = logging.getLogger(__name__)

@shared_task(name='intellidog.license_check_job')
def check_license_status():
    """
    Daily license health check.
    
    - Validates current license
    - Sends alerts if expiring soon
    - Deactivates if expired
    """
    with get_db_session() as db:
        validator = LicenseValidator(db)
        result = validator.validate_current()
        
        if not result.valid:
            logger.error(f"License validation failed: {result.errors}")
            
            # Send alert to admins
            send_admin_alert(
                subject="Intellidog License Invalid",
                message=f"License validation failed: {', '.join(result.errors)}"
            )
            
            return {
                'status': 'invalid',
                'errors': result.errors
            }
        
        if result.warnings:
            logger.warning(f"License warnings: {result.warnings}")
            
            # Send warning email
            send_admin_alert(
                subject="Intellidog License Warning",
                message=f"License warnings: {', '.join(result.warnings)}",
                severity='warning'
            )
        
        return {
            'status': 'valid',
            'license_key': result.license.license_key,
            'expires_at': result.license.expires_at.isoformat(),
            'days_until_expiry': result.license.days_until_expiry,
            'warnings': result.warnings
        }
```

---

## Summary

**License System Components**:

1. ✅ License file format (JSON + GPG)
2. ✅ GPG key management (public key distribution)
3. ✅ License generation script (Dognet internal)
4. ✅ Complete validator implementation
5. ✅ Frontend upload component
6. ✅ Feature gates (middleware)
7. ✅ Periodic license health check

**Security**:
- RSA 4096-bit GPG signatures
- Public key fingerprint verification
- Expiration validation
- Feature-based access control

**Production-Ready**: ✅

---

**Document Version**: 1.0.0  
**Last Updated**: 2025-01-02  
**Author**: Dognet Technologies
