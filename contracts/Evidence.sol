pragma solidity ^0.5.16;

// Creating a Smart Contract
contract Evidence {

    // Structure of evidence
    struct Evidence {
        int evid;
        string name;
        string owner;
        string location;
        string myHash;
        uint256 timestamp;
    }

    Evidence[] public evds;

    // Events for logging
    event EvidenceUploaded(
        int indexed evid,
        string name,
        string owner,
        string location,
        string myHash,
        uint256 timestamp
    );

    event EvidenceVerified(
        int indexed evid,
        uint256 timestamp
    );

    // Function to add evidence details
    function addEvidence(
        int evid,
        string memory name,
        string memory owner,
        string memory location,
        string memory myHash
    ) public {
        uint256 currentTimestamp = block.timestamp;
        Evidence memory e = Evidence(evid, name, owner, location, myHash, currentTimestamp);
        evds.push(e);

        // Emit event
        emit EvidenceUploaded(evid, name, owner, location, myHash, currentTimestamp);
    }

    // Function to get details of evidence
    function getEvidence(
        int evid
    ) public view returns (
        string memory name,
        string memory owner,
        string memory location,
        string memory myHash,
        uint256 timestamp
    ) {
        uint i;
        for (i = 0; i < evds.length; i++) {
            Evidence memory e = evds[i];

            // Check for matching evidence ID
            if (e.evid == evid) {
                return (e.name, e.owner, e.location, e.myHash, e.timestamp);
            }
        }

        // If evidence ID is not found, return default values
        return ("Not Found", "Not Found", "Not Found", "Not Found", 0);
    }

    // Function to verify evidence (logs verification time)
    function verifyEvidence(int evid) public {
        uint256 currentTimestamp = block.timestamp;
        emit EvidenceVerified(evid, currentTimestamp);
    }
}
