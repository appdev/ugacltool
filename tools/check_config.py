#!/usr/bin/env python3
"""Read-only schema or live physical-policy preflight; no mount or device write."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import fnos_storage as storage
import disk_safety


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--schema-only', action='store_true',
                        help='Validate schema only; does not authorize live disk operations')
    args = parser.parse_args()
    try:
        if args.schema_only:
            config = json.loads(args.config.read_text())
        else:
            storage.view.require_host()
            config = storage.private_json(args.config)
        storage.validate_config(config)
        disk_safety.policy_for(config)
        if not args.schema_only:
            disk_safety.check_config(config)
        print(json.dumps({'valid': True, 'scope': 'schema' if args.schema_only else 'physical-policy',
                          'pool_count': len(config['pools']), 'device_writes': False}))
        return 0
    except (storage.ValidationError, OSError, ValueError, KeyError, TypeError) as exc:
        # A malformed config must not dump its potentially private contents.
        print(json.dumps({'valid': False, 'error_type': type(exc).__name__}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
