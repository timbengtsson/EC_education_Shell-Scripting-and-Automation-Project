from utils.functions import runCommand 
import sys
import logging
 
logger = logging.getLogger(__name__)

def getRunningImageRefs() -> list[str]:
    proc = runCommand(["docker", "ps", "--format", "{{.Image}}"])
    if proc.returncode != 0:
        logger.error("docker ps failed") 
        if proc.stderr.strip():
            print(proc.stderr.strip(), file=sys.stderr)
        sys.exit(1)

    refs = [line.strip() for line in proc.stdout.splitlines() if line.strip()] 
    seen = set()
    unique = []
    for r in refs:
        if r not in seen:
            seen.add(r)
            unique.append(r)
    return unique


def ensureImageAvailable(imageRef: str, pullIfMissing: bool = False) -> None:
    if imageExistsLocally(imageRef):
        return

    if not pullIfMissing:
        logger.error("Docker bilden hittades inte lokalt: %s", imageRef) 
        print("Tip: build it first (docker build ...) or pull it (docker pull ...)", file=sys.stderr)
        sys.exit(1)

    # Ok.. So we are not doing this ..atleast not yet
    print(f"Image not found locally, pulling: {imageRef}")
    proc = runCommand(["docker", "pull", imageRef])
    if proc.returncode != 0:
        print(f"ERROR: Failed to pull image: {imageRef}", file=sys.stderr)
        if proc.stderr.strip():
            print(proc.stderr.strip(), file=sys.stderr)
        sys.exit(1)


def imageExistsLocally(imageRef: str) -> bool:
    proc = runCommand(["docker", "image", "inspect", imageRef])
    return proc.returncode == 0