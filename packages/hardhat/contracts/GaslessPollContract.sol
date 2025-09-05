// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title GaslessPollContract
 * @dev A gasless polling system where users sign votes off-chain and votes are automatically batched on-chain
 * Key Features:
 * - Users only interact with a single submitVote() function
 * - Automatic batching when threshold is reached (no manual batch management)
 * - Real-time vote counting with efficient storage
 * - EIP-712 signature verification for security
 * - Gas optimization through batch processing
 */
contract GaslessPollContract is Ownable, EIP712 {
    using ECDSA for bytes32;

    // Type hash for EIP-712 vote signature
    bytes32 private constant VOTE_TYPEHASH =
        keccak256("Vote(uint256 pollId,uint256 optionId,address voter,uint256 nonce)");

    // Poll structure
    struct Poll {
        string question;
        string[] options;
        uint256[] voteCounts;
        bool isActive;
        uint256 createdAt;
        address creator; // Track who created the poll
        uint256 duration; // Poll duration in seconds
    }

    // Vote structure for pending votes
    struct PendingVote {
        uint256 pollId;
        uint256 optionId;
        address voter;
        uint256 nonce;
        bytes signature;
    }

    // State variables
    mapping(uint256 => Poll) public polls;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    mapping(address => uint256) public voterNonces;

    uint256 public pollCount;
    PendingVote[] public pendingVotes;

    // Configuration
    uint256 public autoBatchThreshold = 5; // Auto-process when this many votes are pending
    uint256 public maxBatchSize = 50; // Maximum votes to process in one batch

    // Events
    event PollCreated(uint256 indexed pollId, string question, string[] options, address indexed creator);
    event VoteQueued(uint256 indexed pollId, address indexed voter, uint256 optionId);
    event VotesProcessed(uint256 indexed pollId, uint256 votesProcessed);
    event PollClosed(uint256 indexed pollId);

    constructor() EIP712("GaslessPollContract", "1") Ownable(msg.sender) {}

    /**
     * @dev Create a new poll with given question, options, and duration
     */
    function createPoll(string memory _question, string[] memory _options, uint256 _duration)
        external
        returns (uint256)
    {
        require(bytes(_question).length > 0, "Question cannot be empty");
        require(_options.length >= 2, "Must have at least 2 options");
        require(_options.length <= 10, "Cannot have more than 10 options");
        require(_duration >= 15 minutes, "Duration must be at least 15 minutes");
        require(_duration <= 30 days, "Duration cannot exceed 30 days");

        uint256 pollId = pollCount++;

        // Initialize vote counts array
        uint256[] memory voteCounts = new uint256[](_options.length);

        polls[pollId] = Poll({
            question: _question,
            options: _options,
            voteCounts: voteCounts,
            isActive: true,
            createdAt: block.timestamp,
            creator: msg.sender,
            duration: _duration
        });

        emit PollCreated(pollId, _question, _options, msg.sender);
        return pollId;
    }

    /**
     * @dev Single entry point for voting - handles verification and automatic processing
     * This is the ONLY function users need to interact with
     */
    function submitVote(uint256 _pollId, uint256 _optionId, address _voter, uint256 _nonce, bytes memory _signature)
        external
    {
        require(_pollId < pollCount, "Poll does not exist");
        require(polls[_pollId].isActive, "Poll is not active");
        require(_optionId < polls[_pollId].options.length, "Invalid option");
        require(!hasVoted[_pollId][_voter], "Voter has already voted");
        require(_nonce == voterNonces[_voter], "Invalid nonce");
        require(polls[_pollId].creator != _voter, "Poll creators cannot vote on their own polls");

        // Check if poll has expired
        require(block.timestamp <= polls[_pollId].createdAt + polls[_pollId].duration, "Poll has expired");

        // Verify the signature
        bytes32 structHash = keccak256(abi.encode(VOTE_TYPEHASH, _pollId, _optionId, _voter, _nonce));
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = hash.recover(_signature);
        require(signer == _voter, "Invalid signature");

        // Add to pending votes
        pendingVotes.push(
            PendingVote({pollId: _pollId, optionId: _optionId, voter: _voter, nonce: _nonce, signature: _signature})
        );

        emit VoteQueued(_pollId, _voter, _optionId);

        // Try automatic processing
        _tryAutoProcess();
    }

    /**
     * @dev Automatically process pending votes if threshold is reached
     */
    function _tryAutoProcess() internal {
        if (pendingVotes.length >= autoBatchThreshold) {
            _processPendingVotes();
        }
    }

    /**
     * @dev Process all pending votes and update on-chain state
     */
    function _processPendingVotes() internal {
        uint256 totalPending = pendingVotes.length;
        if (totalPending == 0) return;

        uint256 processCount = totalPending > maxBatchSize ? maxBatchSize : totalPending;
        uint256 votesProcessed = 0;

        // Process votes from the beginning of the array
        for (uint256 i = 0; i < processCount; i++) {
            PendingVote memory vote = pendingVotes[i];

            // Check if poll is still active and not expired
            bool pollExpired = block.timestamp > polls[vote.pollId].createdAt + polls[vote.pollId].duration;

            // Double-check the vote is still valid (prevent replay attacks and handle expired polls)
            if (!hasVoted[vote.pollId][vote.voter] && polls[vote.pollId].isActive && !pollExpired) {
                // Mark as voted and increment vote count
                hasVoted[vote.pollId][vote.voter] = true;
                voterNonces[vote.voter]++;
                polls[vote.pollId].voteCounts[vote.optionId]++;
                votesProcessed++;

                emit VotesProcessed(vote.pollId, 1);
            }
            // If poll expired, we still process the vote to remove it from pending but don't count it
            else if (pollExpired) {
                // Increment nonce to prevent replay but don't count the vote
                voterNonces[vote.voter]++;
            }
        }

        // Remove processed votes by shifting remaining votes to the beginning
        uint256 remaining = totalPending - processCount;
        if (remaining > 0) {
            for (uint256 i = 0; i < remaining; i++) {
                pendingVotes[i] = pendingVotes[processCount + i];
            }
        }

        // Adjust array length
        for (uint256 i = 0; i < processCount; i++) {
            pendingVotes.pop();
        }
    }

    /**
     * @dev Manual trigger for processing pending votes (in case automatic processing fails)
     */
    function processPendingVotes() external {
        _processPendingVotes();
    }

    /**
     * @dev Check if a poll has expired
     */
    function isPollExpired(uint256 _pollId) public view returns (bool) {
        require(_pollId < pollCount, "Poll does not exist");
        return block.timestamp > polls[_pollId].createdAt + polls[_pollId].duration;
    }

    /**
     * @dev Get poll end time
     */
    function getPollEndTime(uint256 _pollId) external view returns (uint256) {
        require(_pollId < pollCount, "Poll does not exist");
        return polls[_pollId].createdAt + polls[_pollId].duration;
    }

    /**
     * @dev Get poll details including current vote counts
     */
    function getPoll(uint256 _pollId)
        external
        view
        returns (
            string memory question,
            string[] memory options,
            uint256[] memory voteCounts,
            bool isActive,
            uint256 createdAt,
            address creator,
            uint256 duration,
            uint256 endTime,
            bool isExpired
        )
    {
        require(_pollId < pollCount, "Poll does not exist");
        Poll memory poll = polls[_pollId];
        bool expired = isPollExpired(_pollId);
        uint256 pollEndTime = poll.createdAt + poll.duration;

        return (
            poll.question,
            poll.options,
            poll.voteCounts,
            poll.isActive && !expired, // Poll is only truly active if not expired
            poll.createdAt,
            poll.creator,
            poll.duration,
            pollEndTime,
            expired
        );
    }

    /**
     * @dev Get the number of pending votes waiting to be processed
     */
    function getPendingVotesCount() external view returns (uint256) {
        return pendingVotes.length;
    }

    /**
     * @dev Get voter's current nonce for signature creation
     */
    function getVoterNonce(address _voter) external view returns (uint256) {
        return voterNonces[_voter];
    }

    /**
     * @dev Check if a voter has voted in a specific poll
     */
    function getHasVoted(uint256 _pollId, address _voter) external view returns (bool) {
        return hasVoted[_pollId][_voter];
    }

    /**
     * @dev Update auto-batch threshold (only owner)
     */
    function updateAutoBatchThreshold(uint256 _threshold) external onlyOwner {
        require(_threshold > 0, "Threshold must be greater than 0");
        autoBatchThreshold = _threshold;
    }

    /**
     * @dev Update max batch size (only owner)
     */
    function updateMaxBatchSize(uint256 _maxSize) external onlyOwner {
        require(_maxSize > 0, "Max size must be greater than 0");
        maxBatchSize = _maxSize;
    }

    /**
     * @dev Get the domain separator for EIP-712
     */
    function getDomainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }
}
