package core

import (
	"bytes"
	"gradeddag/crypto"
	"sync"
	"sync/atomic"
)

type cbcCallBackReq struct {
	Proposer  NodeID
	Round     int
	Reference map[crypto.Digest]NodeID
	BlockHash crypto.Digest
}

type CBC struct {
	proposer  NodeID
	round     int
	c         *Core
	mu        sync.Mutex
	blockHash crypto.Digest
	reference map[crypto.Digest]NodeID
	callBack  chan<- *cbcCallBackReq

	unMutex         sync.Mutex
	unHandleCBCVote []*CBCVoteMsg

	voteNums atomic.Int32
}

func NewCBC(c *Core, proposer NodeID, round int, callBack chan<- *cbcCallBackReq) *CBC {
	return &CBC{
		proposer:  proposer,
		round:     round,
		c:         c,
		callBack:  callBack,
		reference: make(map[crypto.Digest]NodeID),
	}
}

func (c *CBC) ProcessProposal(propose *CBCProposeMsg) {
	if propose.Author != c.proposer || propose.Round != c.round {
		return
	}

	c.mu.Lock()
	c.blockHash = propose.B.Hash()
	c.reference = propose.B.Reference
	c.mu.Unlock()

	c.unMutex.Lock()
	for _, vote := range c.unHandleCBCVote {
		go c.ProcessVote(vote)
	}
	c.unMutex.Unlock()

	vote, _ := NewCBCVoteMsg(c.c.nodeID, propose.B, c.c.sigService)
	c.c.transmitor.Send(c.c.nodeID, NONE, vote) //非线性CBC，直接全广播
	c.c.transmitor.RecvChannel() <- vote
}

func (c *CBC) ProcessVote(vote *CBCVoteMsg) {
	if vote.Proposer != c.proposer || vote.Round != c.round {
		return
	}

	c.mu.Lock()
	if !bytes.Equal(c.blockHash[:], vote.BlockHash[:]) {
		c.unMutex.Lock()
		c.unHandleCBCVote = append(c.unHandleCBCVote, vote)
		c.unMutex.Unlock()
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	nums := c.voteNums.Add(1)
	if nums == int32(c.c.committee.HightThreshold()) { //2f+1?
		c.callBack <- &cbcCallBackReq{
			Proposer:  c.proposer,
			Round:     c.round,
			Reference: c.reference,
			BlockHash: vote.BlockHash,
		}
	}
}
