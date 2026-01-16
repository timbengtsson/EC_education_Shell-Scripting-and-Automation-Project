from typing import Any 
from utils.functions import runCommand, parseArgs
import json
import sys
import logging
 
logger = logging.getLogger(__name__)

"""
This function runs Trivy and returns the scan results as a dictionary.
"""
def scanImageWithTrivy(imageRef: str) -> dict[str, Any]:
    cmd = ["trivy", "image", "--format", "json", "--quiet", imageRef]
    proc = runCommand(cmd) 

    if proc.returncode != 0:
        logger.error("Trivy scan failade för %s", imageRef) 
        if proc.stderr.strip():
            print(proc.stderr.strip(), file=sys.stderr)
        sys.exit(1)

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        logger.error("Kunde inte parsa Trivy JSON output.") 
        sys.exit(1)


