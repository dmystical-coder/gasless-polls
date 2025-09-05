// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title GaslessPollContract
 * @dev A smart contract for gasless polling using EIP-712 signatures
 * Users sign vote messages off-chain, which are then batched and submitted on-chain
 */
contract GaslessPollContract is Ownable, EIP712 {
    using ECDSA for bytes32;

    // EIP-712 type hash for vote signatures
    bytes32 public constant VOTE_TYPEHASH =
        keccak256("Vote(uint256 pollId,uint256 optionIndex,address voter,uint256 nonce)");

    // Poll structure
    struct Poll {
        string question;
        string[] options;
        address creator;
        uint256 endTime;
        bool active;
    }

    // Vote structure for batch processing
    struct Vote {
        uint256 pollId;
        uint256 optionIndex;
        address voter;
        uint256 nonce;
    }

    // State variables
    mapping(uint256 => Poll) public polls;
    mapping(uint256 => mapping(uint256 => uint256)) public voteCounts; // pollId => optionIndex => count
    mapping(uint256 => mapping(address => bool)) public hasVoted; // pollId => voter => hasVoted
    mapping(address => uint256) public nonces; // voter nonces for replay protection

    // Batch submission tracking
    mapping(uint256 => Vote[]) public pendingVotes; // pollId => pending votes array
    mapping(uint256 => bytes[]) public pendingSignatures; // pollId => pending signatures array
    mapping(uint256 => bool) public batchProcessed; // pollId => whether final batch was processed

    uint256 public pollCount;

    // Batch submission settings
    uint256 public minBatchSize = 10; // Minimum votes to trigger early batch submission
    uint256 public maxBatchSize = 100; // Maximum votes per batch transaction

    // Events
    event PollCreated(uint256 indexed pollId, string question, address indexed creator, uint256 endTime);

    event VoteCast(uint256 indexed pollId, uint256 optionIndex, address indexed voter);

    event VotesBatched(uint256 indexed pollId, uint256 totalVotes);

    event PollEnded(uint256 indexed pollId);

    event VoteQueued(uint256 indexed pollId, address indexed voter, uint256 optionIndex);

    event BatchTriggered(uint256 indexed pollId, uint256 batchSize, string reason);

    // Custom errors
    error PollNotActive();
    error PollExpired();
    error InvalidOption();
    error AlreadyVoted();
    error InvalidSignature();
    error InvalidNonce();
    error UnauthorizedEndPoll();
    error InvalidPollDuration();
    error InsufficientOptions();
    error TooManyOptions();
    error BatchMismatch();
    error EmptyBatch();
    error BatchAlreadyProcessed();
    error PollStillActive();
    error BatchSizeExceeded();

    constructor(address _owner) Ownable(_owner) EIP712("GaslessPoll", "1") {}

    /**
     * @dev Create a new poll
     * @param _question The poll question
     * @param _options Array of poll options
     * @param _duration Duration of the poll in seconds
     * @return The ID of the created poll
     */
    function createPoll(string memory _question, string[] memory _options, uint256 _duration)
        external
        returns (uint256)
    {
        if (_options.length < 2) revert InsufficientOptions();
        if (_options.length > 10) revert TooManyOptions();
        if (_duration == 0) revert InvalidPollDuration();

        uint256 pollId = pollCount++;

        Poll storage poll = polls[pollId];
        poll.question = _question;
        poll.options = _options;
        poll.creator = msg.sender;
        poll.endTime = block.timestamp + _duration;
        poll.active = true;

        emit PollCreated(pollId, _question, msg.sender, poll.endTime);

        return pollId;
    }

    /**
     * @dev Submit a vote signature to be batched (gasless for users)
     * @param vote The vote data
     * @param signature The EIP-712 signature
     */
    function queueVote(Vote calldata vote, bytes calldata signature) external {
        Poll storage poll = polls[vote.pollId];

        // Validate poll state
        if (!poll.active) revert PollNotActive();
        if (block.timestamp > poll.endTime) revert PollExpired();
        if (vote.optionIndex >= poll.options.length) revert InvalidOption();
        if (hasVoted[vote.pollId][vote.voter]) revert AlreadyVoted();
        if (nonces[vote.voter] != vote.nonce) revert InvalidNonce();

        // Verify EIP-712 signature (but don't process vote yet)
        bytes32 structHash = keccak256(abi.encode(VOTE_TYPEHASH, vote.pollId, vote.optionIndex, vote.voter, vote.nonce));
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = hash.recover(signature);

        if (signer != vote.voter) revert InvalidSignature();

        // Queue the vote
        pendingVotes[vote.pollId].push(vote);
        pendingSignatures[vote.pollId].push(signature);

        // Mark as voted to prevent double voting
        hasVoted[vote.pollId][vote.voter] = true;
        nonces[vote.voter]++;

        emit VoteQueued(vote.pollId, vote.voter, vote.optionIndex);

        // Check if we should trigger early batch submission
        if (pendingVotes[vote.pollId].length >= minBatchSize) {
            _processPendingBatch(vote.pollId, "MinBatchSizeReached");
        }
    }

    /**
     * @dev Process final batch when poll ends (can be called by anyone after poll expires)
     * @param pollId The ID of the poll
     */
    function processFinalBatch(uint256 pollId) external {
        Poll storage poll = polls[pollId];

        if (poll.active && block.timestamp <= poll.endTime) revert PollStillActive();
        if (batchProcessed[pollId]) revert BatchAlreadyProcessed();

        _processPendingBatch(pollId, "PollEnded");
        batchProcessed[pollId] = true;

        // Auto-end poll if still marked as active
        if (poll.active) {
            poll.active = false;
            emit PollEnded(pollId);
        }
    }

    /**
     * @dev Force process current batch (owner only, for emergencies)
     * @param pollId The ID of the poll
     */
    function forceProcessBatch(uint256 pollId) external onlyOwner {
        _processPendingBatch(pollId, "ForceProcessed");
    }

    /**
     * @dev Internal function to process pending votes batch
     * @param pollId The ID of the poll
     * @param reason Reason for batch processing
     */
    function _processPendingBatch(uint256 pollId, string memory reason) internal {
        Vote[] storage votes = pendingVotes[pollId];
        bytes[] storage signatures = pendingSignatures[pollId];

        if (votes.length == 0) return; // No votes to process

        uint256 batchSize = votes.length;
        if (batchSize > maxBatchSize) {
            batchSize = maxBatchSize;
        }

        // Process votes and update counts
        for (uint256 i = 0; i < batchSize; i++) {
            voteCounts[pollId][votes[i].optionIndex]++;
            emit VoteCast(pollId, votes[i].optionIndex, votes[i].voter);
        }

        // Remove processed votes from pending arrays
        for (uint256 i = 0; i < batchSize; i++) {
            votes[i] = votes[votes.length - 1];
            signatures[i] = signatures[signatures.length - 1];
            votes.pop();
            signatures.pop();
        }

        emit BatchTriggered(pollId, batchSize, reason);
        emit VotesBatched(pollId, batchSize);
    }

    /**
     * @dev Submit a batch of votes with their signatures (original method, still available)
     * @param votes Array of vote data
     * @param signatures Array of corresponding signatures
     */
    function submitVoteBatch(Vote[] calldata votes, bytes[] calldata signatures) external {
        if (votes.length != signatures.length) revert BatchMismatch();
        if (votes.length == 0) revert EmptyBatch();

        for (uint256 i = 0; i < votes.length; i++) {
            _processVote(votes[i], signatures[i]);
        }

        // Emit batch event for the first poll (assuming all votes are for the same poll)
        if (votes.length > 0) {
            emit VotesBatched(votes[0].pollId, votes.length);
        }
    }

    /**
     * @dev Process a single vote with signature verification
     * @param vote The vote data
     * @param signature The EIP-712 signature
     */
    function _processVote(Vote calldata vote, bytes calldata signature) internal {
        Poll storage poll = polls[vote.pollId];

        // Validate poll state
        if (!poll.active) revert PollNotActive();
        if (block.timestamp > poll.endTime) revert PollExpired();
        if (vote.optionIndex >= poll.options.length) revert InvalidOption();
        if (hasVoted[vote.pollId][vote.voter]) revert AlreadyVoted();
        if (nonces[vote.voter] != vote.nonce) revert InvalidNonce();

        // Verify EIP-712 signature
        bytes32 structHash = keccak256(abi.encode(VOTE_TYPEHASH, vote.pollId, vote.optionIndex, vote.voter, vote.nonce));
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = hash.recover(signature);

        if (signer != vote.voter) revert InvalidSignature();

        // Process the vote
        hasVoted[vote.pollId][vote.voter] = true;
        voteCounts[vote.pollId][vote.optionIndex]++;
        nonces[vote.voter]++;

        emit VoteCast(vote.pollId, vote.optionIndex, vote.voter);
    }

    /**
     * @dev End a poll (only creator or owner can end)
     * @param pollId The ID of the poll to end
     */
    function endPoll(uint256 pollId) external {
        Poll storage poll = polls[pollId];

        if (!poll.active) revert PollNotActive();
        if (msg.sender != poll.creator && msg.sender != owner()) {
            revert UnauthorizedEndPoll();
        }

        poll.active = false;
        emit PollEnded(pollId);
    }

    /**
     * @dev Get poll details
     * @param pollId The ID of the poll
     * @return question Poll question
     * @return options Array of poll options
     * @return creator Address of poll creator
     * @return endTime Poll end timestamp
     * @return active Whether poll is active
     */
    function getPoll(uint256 pollId)
        external
        view
        returns (string memory question, string[] memory options, address creator, uint256 endTime, bool active)
    {
        Poll storage poll = polls[pollId];
        return (poll.question, poll.options, poll.creator, poll.endTime, poll.active);
    }

    /**
     * @dev Get vote counts for a poll
     * @param pollId The ID of the poll
     * @return Array of vote counts for each option
     */
    function getVoteCounts(uint256 pollId) external view returns (uint256[] memory) {
        Poll storage poll = polls[pollId];
        uint256[] memory counts = new uint256[](poll.options.length);

        for (uint256 i = 0; i < poll.options.length; i++) {
            counts[i] = voteCounts[pollId][i];
        }

        return counts;
    }

    /**
     * @dev Check if an address has voted in a poll
     * @param pollId The ID of the poll
     * @param voter The address to check
     * @return Whether the address has voted
     */
    function hasVotedInPoll(uint256 pollId, address voter) external view returns (bool) {
        return hasVoted[pollId][voter];
    }

    /**
     * @dev Get the current nonce for an address
     * @param voter The address to get nonce for
     * @return The current nonce
     */
    function getNonce(address voter) external view returns (uint256) {
        return nonces[voter];
    }

    /**
     * @dev Check if a poll is active and not expired
     * @param pollId The ID of the poll
     * @return Whether the poll is currently active for voting
     */
    function isPollActive(uint256 pollId) external view returns (bool) {
        Poll storage poll = polls[pollId];
        return poll.active && block.timestamp <= poll.endTime;
    }

    /**
     * @dev Get total number of polls created
     * @return The total poll count
     */
    function getTotalPolls() external view returns (uint256) {
        return pollCount;
    }

    /**
     * @dev Get pending votes count for a poll
     * @param pollId The ID of the poll
     * @return Number of pending votes
     */
    function getPendingVotesCount(uint256 pollId) external view returns (uint256) {
        return pendingVotes[pollId].length;
    }

    /**
     * @dev Get batch settings
     * @return minBatch Minimum batch size
     * @return maxBatch Maximum batch size
     */
    function getBatchSettings() external view returns (uint256 minBatch, uint256 maxBatch) {
        return (minBatchSize, maxBatchSize);
    }

    /**
     * @dev Set batch settings (owner only)
     * @param _minBatchSize New minimum batch size
     * @param _maxBatchSize New maximum batch size
     */
    function setBatchSettings(uint256 _minBatchSize, uint256 _maxBatchSize) external onlyOwner {
        require(_minBatchSize > 0 && _maxBatchSize > _minBatchSize, "Invalid batch sizes");
        minBatchSize = _minBatchSize;
        maxBatchSize = _maxBatchSize;
    }

    /**
     * @dev Emergency function to pause all polls (owner only)
     */
    function emergencyPauseAll() external onlyOwner {
        // Implementation for emergency pause if needed
        // This could set a global pause state
    }

    // Receive function to accept ETH
    receive() external payable {}
}
