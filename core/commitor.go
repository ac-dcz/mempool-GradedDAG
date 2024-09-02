package core

import (
	"gradeddag/crypto"
	"gradeddag/logger"
	"gradeddag/store"
	"sync"
)

type LocalDAG struct {
	muBlock      *sync.RWMutex
	blockDigests map[crypto.Digest]NodeID // store hash of block that has received
	muDAG        *sync.RWMutex
	localDAG     map[int]map[NodeID]crypto.Digest // local DAG
	edgesDAG     map[int]map[NodeID]map[crypto.Digest]NodeID
	muGrade      *sync.RWMutex
	gradeDAG     map[int]map[NodeID]int
}

func NewLocalDAG() *LocalDAG {
	return &LocalDAG{
		muBlock:      &sync.RWMutex{},
		muDAG:        &sync.RWMutex{},
		muGrade:      &sync.RWMutex{},
		blockDigests: make(map[crypto.Digest]NodeID),
		localDAG:     make(map[int]map[NodeID]crypto.Digest),
		gradeDAG:     make(map[int]map[NodeID]int),
		edgesDAG:     make(map[int]map[NodeID]map[crypto.Digest]NodeID),
	}
}

// IsReceived: digests is received ?
func (local *LocalDAG) IsReceived(digests ...crypto.Digest) (bool, []crypto.Digest) {
	local.muBlock.RLock()
	defer local.muBlock.RUnlock()

	var miss []crypto.Digest
	var flag bool = true
	for _, d := range digests {
		if _, ok := local.blockDigests[d]; !ok {
			miss = append(miss, d)
			flag = false
		}
	}

	return flag, miss
}

func (local *LocalDAG) ReceiveBlock(round int, node NodeID, digest crypto.Digest, references map[crypto.Digest]NodeID) {
	local.muBlock.Lock()
	local.blockDigests[digest] = node
	local.muBlock.Unlock()

	local.muDAG.Lock()
	vslot, ok := local.localDAG[round]
	eslot := local.edgesDAG[round]
	if !ok {
		vslot = make(map[NodeID]crypto.Digest)
		eslot = make(map[NodeID]map[crypto.Digest]NodeID)
		local.localDAG[round] = vslot
		local.edgesDAG[round] = eslot
	}
	vslot[node] = digest
	eslot[node] = references

	local.muDAG.Unlock()
}

func (local *LocalDAG) GetRoundReceivedBlockNums(round int) (nums, grade2nums int) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()
	local.muGrade.RLock()
	defer local.muGrade.RUnlock()

	nums = len(local.localDAG[round])
	if round%WaveRound == 0 {
		for _, g := range local.gradeDAG[round] {
			if g == GradeTwo {
				grade2nums++
			}
		}
	}

	return
}

func (local *LocalDAG) GetReceivedBlock(round int, node NodeID) (crypto.Digest, bool) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()
	if slot, ok := local.localDAG[round]; ok {
		d, ok := slot[node]
		return d, ok
	}
	return crypto.Digest{}, false
}

func (local *LocalDAG) GetReceivedBlockReference(round int, node NodeID) (map[crypto.Digest]NodeID, bool) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()
	if slot, ok := local.edgesDAG[round]; ok {
		reference, ok := slot[node]
		return reference, ok
	}
	return nil, false
}

func (local *LocalDAG) GetRoundReceivedBlock(round int) (digests map[crypto.Digest]NodeID) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()
	digests = make(map[crypto.Digest]NodeID)
	for id, d := range local.localDAG[round] {
		digests[d] = id
	}

	return digests
}

func (local *LocalDAG) GetGrade(round, node int) (grade int) {
	if round%WaveRound == 0 {
		local.muGrade.RLock()
		if slot, ok := local.gradeDAG[round]; !ok {
			return 0
		} else {
			grade = slot[NodeID(node)]
		}
		local.muGrade.RUnlock()
	}
	return
}

func (local *LocalDAG) UpdateGrade(round, node, grade int) {
	if round%WaveRound == 0 {
		local.muGrade.Lock()

		slot, ok := local.gradeDAG[round]
		if !ok {
			slot = make(map[NodeID]int)
			local.gradeDAG[round] = slot
		}
		if grade > slot[NodeID(node)] {
			slot[NodeID(node)] = grade
		}

		local.muGrade.Unlock()
	}
}

type Commitor struct {
	elector       *Elector
	commitChannel chan<- *Block
	localDAG      *LocalDAG
	commitBlocks  map[crypto.Digest]struct{}
	curWave       int
	notify        chan int
	inner         chan crypto.Digest
	store         *store.Store
	N             int
}

func NewCommitor(electot *Elector, localDAG *LocalDAG, store *store.Store, commitChannel chan<- *Block, N int) *Commitor {
	c := &Commitor{
		elector:       electot,
		localDAG:      localDAG,
		commitChannel: commitChannel,
		commitBlocks:  make(map[crypto.Digest]struct{}),
		curWave:       -1,
		notify:        make(chan int, 100),
		store:         store,
		inner:         make(chan crypto.Digest),
		N:             N,
	}
	go c.run()
	return c
}

func (c *Commitor) run() {

	go func() {
		for digest := range c.inner {
			if block, err := getBlock(c.store, digest); err != nil {
				logger.Warn.Println(err)
			} else {
				if block.Batch.ID != -1 {
					//BenchMark Log
					logger.Info.Printf("commit Block round %d node %d batch_id %d \n", block.Round, block.Author, block.Batch.ID)
				}
				c.commitChannel <- block
			}
		}
	}()

	for num := range c.notify {
		if num > c.curWave {
			if leader := c.elector.GetLeader(num); leader != NONE {

				var leaderQ [][2]int
				leaderQ = append(leaderQ, [2]int{int(leader), num * 2})
				for i := num - 1; i > c.curWave; i-- {
					if node := c.elector.GetLeader(i); node != NONE {
						leaderQ = append(leaderQ, [2]int{int(node), i * 2})
					}
				}
				c.commitLeaderQueue(leaderQ)
				c.curWave = num

			}
		}
	}
}

func (c *Commitor) commitLeaderQueue(q [][2]int) {

	nextRound := c.curWave * 2
	for i := len(q) - 1; i >= 0; i-- {
		leader, round := q[i][0], q[i][1]
		var sortC []crypto.Digest
		var (
			qDigest []crypto.Digest
			qNode   []NodeID
		)
		if block, ok := c.localDAG.GetReceivedBlock(round, NodeID(leader)); !ok {
			logger.Error.Println("commitor : not received block")
			continue
		} else {
			qDigest = append(qDigest, block)
			qNode = append(qNode, NodeID(leader))
			for len(qDigest) > 0 && round >= nextRound {
				n := len(qDigest)
				for n > 0 {
					block := qDigest[0]
					node := qNode[0]
					if _, ok := c.commitBlocks[block]; !ok {
						sortC = append(sortC, block)       // seq commit vector
						c.commitBlocks[block] = struct{}{} // commit flag

						if ref, ok := c.localDAG.GetReceivedBlockReference(round, node); !ok {
							logger.Error.Println("commitor : not received block reference")
						} else {
							for digest, node := range ref {
								qDigest = append(qDigest, digest)
								qNode = append(qNode, node)
							}
						}
					}
					qDigest = qDigest[1:]
					qNode = qNode[1:]
					n--
				} //for
				round--
			} //for
		}

		for i := len(sortC) - 1; i >= 0; i-- {
			c.inner <- sortC[i] // SeqCommit
		}
		nextRound = q[i][1]
	} //for
}

func (c *Commitor) NotifyToCommit(waveNum int) {
	c.notify <- waveNum
}
