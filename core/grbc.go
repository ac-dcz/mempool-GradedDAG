package core

import (
	"gradeddag/crypto"
	"gradeddag/logger"
	"sync"
	"sync/atomic"
)

const (
	NotifyOutPut = iota
	UpdateGrade
)

type grbcCallBackReq struct {
	digest    crypto.Digest
	nodeID    NodeID
	reference map[crypto.Digest]NodeID
	round     int
	grade     int
	tag       int
}

type GRBC struct {
	nodeID   NodeID
	proposer NodeID
	round    int

	digest    atomic.Value
	grade     atomic.Int32
	reference atomic.Value

	sigService *crypto.SigService
	transmitor *Transmitor
	committee  Committee

	echoMu       *sync.Mutex
	unHandleEcho []*EchoMsg
	echoCnt      atomic.Int32

	readyMu       *sync.Mutex
	unHandleReady []*ReadyMsg
	readyCnt      atomic.Int32

	rflag atomic.Bool
	once  sync.Once

	callBackChannel chan<- *grbcCallBackReq
}

func NewGRBC(corer *Core, proposer NodeID, round int, callBackChannel chan<- *grbcCallBackReq) *GRBC {
	grbc := &GRBC{
		proposer:        proposer,
		round:           round,
		echoMu:          &sync.Mutex{},
		readyMu:         &sync.Mutex{},
		once:            sync.Once{},
		sigService:      corer.sigService,
		transmitor:      corer.transmitor,
		committee:       corer.committee,
		nodeID:          corer.nodeID,
		callBackChannel: callBackChannel,
	}

	return grbc
}

func (g *GRBC) processPropose(block *Block) {

	//Step 1: store digest
	digest := block.Hash()
	g.digest.Store(digest)
	g.reference.Store(block.Reference)

	//Step 2: send echo message
	echo, err := NewEchoMsg(g.nodeID, block.Author, digest, block.Round, g.sigService)
	if err != nil {
		logger.Warn.Println(err)
	}

	g.transmitor.Send(g.nodeID, NONE, echo)
	g.transmitor.RecvChannel() <- echo

	//Step 3: handle remain msg
	g.echoMu.Lock()
	for _, echo := range g.unHandleEcho {
		go g.processEcho(echo)
	}
	g.unHandleEcho = nil
	g.echoMu.Unlock()

	g.readyMu.Lock()
	for _, r := range g.unHandleReady {
		go g.processReady(r)
	}
	g.unHandleReady = nil
	g.readyMu.Unlock()

}

func (g *GRBC) processEcho(echo *EchoMsg) {
	//Step 1: compare hash
	if val := g.digest.Load(); val == nil {
		g.echoMu.Lock()
		g.unHandleEcho = append(g.unHandleEcho, echo)
		g.echoMu.Unlock()
		return
	} else {
		hash := val.(crypto.Digest)
		if hash != echo.BlockHash {
			return
		}
	}

	//Step 2: 2f+1?
	if g.echoCnt.Add(1) == int32(g.committee.HightThreshold()) && !g.rflag.Load() {
		// ready
		g.once.Do(func() {
			ready, _ := NewReadyMsg(g.nodeID, g.proposer, echo.BlockHash, echo.Round, g.sigService)
			g.transmitor.Send(g.nodeID, NONE, ready)
			g.transmitor.RecvChannel() <- ready
			g.grade.Store(GradeOne)
			g.rflag.Store(true)

			//TODO: callback
			g.callBackChannel <- &grbcCallBackReq{
				nodeID:    g.proposer,
				digest:    echo.BlockHash,
				round:     g.round,
				grade:     GradeOne,
				tag:       NotifyOutPut,
				reference: g.reference.Load().(map[crypto.Digest]NodeID),
			}
		})
	}

}

func (g *GRBC) processReady(ready *ReadyMsg) {
	//Step 1: compare hash
	if val := g.digest.Load(); val == nil {
		g.readyMu.Lock()
		g.unHandleReady = append(g.unHandleReady, ready)
		g.readyMu.Unlock()
		return
	} else {
		hash := val.(crypto.Digest)
		if hash != ready.BlockHash {
			return
		}
	}

	//Step 2:
	if cnt := g.readyCnt.Add(1); cnt == int32(g.committee.LowThreshold()) && !g.rflag.Load() {
		g.once.Do(func() {
			ready, _ := NewReadyMsg(g.nodeID, g.proposer, ready.BlockHash, ready.Round, g.sigService)
			g.transmitor.Send(g.nodeID, NONE, ready)
			g.transmitor.RecvChannel() <- ready
			g.grade.Store(GradeOne)
			g.rflag.Store(true)

			//TODO: callback
			g.callBackChannel <- &grbcCallBackReq{
				nodeID:    g.proposer,
				digest:    ready.BlockHash,
				round:     g.round,
				grade:     GradeOne,
				tag:       NotifyOutPut,
				reference: g.reference.Load().(map[crypto.Digest]NodeID),
			}
		})
	} else if cnt == int32(g.committee.HightThreshold()) {
		g.grade.Store(GradeTwo)

		//TODO: update grade
		g.callBackChannel <- &grbcCallBackReq{
			nodeID: g.proposer,
			digest: ready.BlockHash,
			round:  ready.Round,
			grade:  GradeTwo,
			tag:    UpdateGrade,
		}
	}

}

func (g *GRBC) Grade() int {
	return int(g.grade.Load())
}
