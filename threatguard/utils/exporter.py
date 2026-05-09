

from __future__ import annotations

import csv
import json
import os
from datetime import datetime
from typing import Sequence

from threatguard.core.packet import Packet

def export_to_json(packets: Sequence[Packet], filepath: str) -> int:
    
    export_data = {
        "metadata": {
            "tool": "ThreatGuard IDPS",
            "export_time": datetime.now().isoformat(),
            "total_records": len(packets),
            "malicious_count": sum(1 for p in packets if p.is_malicious),
            "blocked_count": sum(1 for p in packets if p.is_blocked),
        },
        "packets": [p.to_dict() for p in packets],
    }

    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)

    return len(packets)

def export_to_csv(packets: Sequence[Packet], filepath: str) -> int:
    
    if not packets:
        return 0

    headers = [
        "ID", "Timestamp", "Source IP", "Source Port", "Destination IP",
        "Destination Port", "Protocol", "Length", "TTL", "Flags",
        "Is Malicious", "Threat Type", "Confidence", "Model Used",
        "Is Blocked", "Block Reason", "Payload Preview",
    ]

    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for p in packets:
            writer.writerow([
                p.id,
                p.timestamp.isoformat(),
                p.src_ip,
                p.src_port,
                p.dst_ip,
                p.dst_port,
                p.protocol.value,
                p.length,
                p.ttl,
                p.flags,
                p.is_malicious,
                p.threat_type.name,
                f"{p.confidence:.4f}",
                p.model_used,
                p.is_blocked,
                p.block_reason,
                p.payload_preview,
            ])

    return len(packets)

def export_to_txt(packets: Sequence[Packet], filepath: str) -> int:
    
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

    separator = "=" * 80

    with open(filepath, "w", encoding="utf-8") as f:
                
        f.write(f"{separator}\n")
        f.write("  THREATGUARD IDPS — TRAFFIC LOG EXPORT\n")
        f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Total Records: {len(packets)}\n")
        f.write(f"  Malicious: {sum(1 for p in packets if p.is_malicious)}\n")
        f.write(f"  Blocked: {sum(1 for p in packets if p.is_blocked)}\n")
        f.write(f"{separator}\n\n")

        for i, p in enumerate(packets, 1):
            f.write(f"─── Packet #{i} {'[BLOCKED]' if p.is_blocked else '[MALICIOUS]' if p.is_malicious else '[CLEAN]'} ───\n")
            f.write(f"  ID:          {p.id}\n")
            f.write(f"  Timestamp:   {p.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')}\n")
            f.write(f"  Source:      {p.src_ip}:{p.src_port}\n")
            f.write(f"  Destination: {p.dst_ip}:{p.dst_port}\n")
            f.write(f"  Protocol:    {p.protocol.value}\n")
            f.write(f"  Length:      {p.length} bytes\n")
            f.write(f"  TTL:         {p.ttl}\n")
            f.write(f"  Flags:       {p.flags or 'N/A'}\n")

            if p.is_malicious:
                f.write(f"  Threat Type: {p.threat_type.display_name}\n")
                f.write(f"  Severity:    {p.threat_type.severity}\n")
                f.write(f"  Confidence:  {p.confidence:.1%}\n")
                f.write(f"  ML Model:    {p.model_used}\n")

            if p.is_blocked:
                f.write(f"  Block Reason: {p.block_reason}\n")

            if p.payload_preview:
                f.write(f"  Payload:     {p.payload_preview}\n")

            f.write("\n")

        f.write(f"{separator}\n")
        f.write("  END OF LOG\n")
        f.write(f"{separator}\n")

    return len(packets)
