package core

import (
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
	blockHash atomic.Value
	reference atomic.Value
	callBack  chan<- *cbcCallBackReq

	unMutex         sync.Mutex
	unHandleCBCVote []*CBCVoteMsg

	voteNums atomic.Int32
}

func NewCBC(c *Core, proposer NodeID, round int, callBack chan<- *cbcCallBackReq) *CBC {
	return &CBC{
		proposer: proposer,
		round:    round,
		c:        c,
		callBack: callBack,
	}
}

func (c *CBC) ProcessProposal(propose *CBCProposeMsg) {
	if propose.Author != c.proposer || propose.Round != c.round {
		return
	}
	if c.blockHash.Load() != nil {
		return
	}
	c.reference.Store(propose.B.Reference)
	c.blockHash.Store(propose.B.Hash())
	c.unMutex.Lock()
	for _, vote := range c.unHandleCBCVote {
		go c.ProcessVote(vote)
	}
	c.unMutex.Unlock()
	vote, _ := NewCBCVoteMsg(c.proposer, propose.B, c.c.sigService)
	c.c.transmitor.Send(c.proposer, NONE, vote) //非线性CBC，直接全广播
}

func (c *CBC) ProcessVote(vote *CBCVoteMsg) {
	if vote.Proposer != c.proposer || vote.Round != c.round {
		return
	}
	c.unMutex.Lock()
	if c.blockHash.Load() == nil {
		c.unHandleCBCVote = append(c.unHandleCBCVote, vote)
		c.unMutex.Unlock()
		return
	}
	c.unMutex.Unlock()
	if c.blockHash.Load() != vote.BlockHash {
		return
	}
	nums := c.voteNums.Add(1)
	if nums == int32(c.c.committee.HightThreshold()) { //2f+1?
		c.callBack <- &cbcCallBackReq{
			Proposer:  c.proposer,
			Round:     c.round,
			Reference: c.reference.Load().(map[crypto.Digest]NodeID),
			BlockHash: vote.BlockHash,
		}
	}
}
